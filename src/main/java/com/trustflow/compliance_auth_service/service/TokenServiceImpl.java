package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.dto.*;
import com.trustflow.compliance_auth_service.exception.DuplicateEmailException;
import com.trustflow.compliance_auth_service.repository.RoleRepository;
import com.trustflow.compliance_auth_service.repository.UserRepository;
import com.trustflow.compliance_auth_service.domain.Role;
import com.trustflow.compliance_auth_service.domain.User;
import com.trustflow.compliance_auth_service.domain.enums.PermissionValueType;
import com.trustflow.compliance_auth_service.domain.enums.RoleType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final AuthenticationManager authenticationManager;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository registeredClientRepository;
    private final JwtDecoder jwtDecoder;
    private final JdbcTemplate jdbcTemplate;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final CompanyEventPublisher companyEventPublisher;
    private final CmsCompanyInfoClient cmsCompanyInfoClient;

    @Override
    @Transactional
    public TokenResponse authenticate(String username, String password, String clientId) {
        log.info("Authenticating user: {} for client: {}", username, clientId);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client ID: " + clientId);
        }

        // Генерация Access Token
        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(buildAuthorizationServerContext())
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .build();
        OAuth2AccessToken accessToken=null;
        try{
            accessToken = generateAccessToken(accessTokenContext, registeredClient.getScopes());
        }catch (RuntimeException e){
            log.error("error tokenGenerator.generate", e);
        }
        if (accessToken == null) {
            throw new IllegalStateException("Failed to generate access token");
        }

        // Генерация Refresh Token
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(buildAuthorizationServerContext())
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2RefreshToken refreshToken = (OAuth2RefreshToken) tokenGenerator.generate(refreshTokenContext);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(authentication.getName())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        authorizationService.save(authorization);

        log.info("Successfully authenticated user: {}", username);

        return TokenResponse.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : null)
                .tokenType("Bearer")
                .expiresIn(accessToken.getExpiresAt() != null ?
                        accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond() : 900L)
                .scope(String.join(" ", registeredClient.getScopes()))
                .build();
    }

    @Override
    @Transactional
    public TokenResponse refreshAccessToken(String refreshTokenValue, String clientId) {
        log.info("Refreshing access token for client: {}", clientId);

        OAuth2Authorization authorization = authorizationService.findByToken(
                refreshTokenValue,
                OAuth2TokenType.REFRESH_TOKEN
        );

        if (authorization == null) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null ||
                !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            throw new IllegalArgumentException("Client mismatch");
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getRefreshToken();

        if (refreshToken == null || refreshToken.isExpired()) {
            throw new IllegalArgumentException("Refresh token expired");
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessTokenAuth = authorization.getAccessToken();
        Set<GrantedAuthority> authorities = Set.of();

        if (accessTokenAuth != null && accessTokenAuth.getClaims() != null) {
            Object authoritiesObj = accessTokenAuth.getClaims().get("authorities");
            if (authoritiesObj instanceof java.util.List) {
                authorities = ((java.util.List<?>) authoritiesObj).stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .map(auth -> (GrantedAuthority) () -> auth)
                        .collect(Collectors.toSet());
            }
        }

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authorization.getPrincipalName(),
                null,
                authorities
        );

        // Генерация нового Access Token
        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(buildAuthorizationServerContext())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .build();

        OAuth2AccessToken newAccessToken = generateAccessToken(accessTokenContext, authorization.getAuthorizedScopes());
        if (newAccessToken == null) {
            throw new IllegalStateException("Failed to generate new access token");
        }

        // Генерация нового Refresh Token
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(buildAuthorizationServerContext())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorization(authorization)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .build();

        OAuth2RefreshToken newRefreshToken = (OAuth2RefreshToken) tokenGenerator.generate(refreshTokenContext);

        authorizationService.remove(authorization);

        OAuth2Authorization newAuthorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .build();

        authorizationService.save(newAuthorization);

        log.info("Successfully refreshed access token");

        return TokenResponse.builder()
                .accessToken(newAccessToken.getTokenValue())
                .refreshToken(newRefreshToken != null ? newRefreshToken.getTokenValue() : refreshTokenValue)
                .tokenType("Bearer")
                .expiresIn(newAccessToken.getExpiresAt() != null ?
                        newAccessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond() : 900L)
                .scope(String.join(" ", authorization.getAuthorizedScopes()))
                .build();
    }

    @Override
    @Transactional
    public void revokeToken(String tokenValue) {
        log.info("Revoking token");

        OAuth2Authorization authorization = authorizationService.findByToken(
                tokenValue,
                OAuth2TokenType.ACCESS_TOKEN
        );

        if (authorization == null) {
            authorization = authorizationService.findByToken(
                    tokenValue,
                    OAuth2TokenType.REFRESH_TOKEN
            );
        }

        if (authorization != null) {
            authorizationService.remove(authorization);
            log.info("Token revoked successfully");
        }
    }

    @Override
    public boolean validateToken(String tokenValue) {
        try {
            Jwt jwt = jwtDecoder.decode(tokenValue);
            return jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now());
        } catch (JwtException e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public TokenInfoDto getTokenInfo(String tokenValue) {
        try {
            Jwt jwt = jwtDecoder.decode(tokenValue);

            Set<String> roles = jwt.getClaim("roles");
            Set<String> scopes = jwt.getClaim("scope");

            return TokenInfoDto.builder()
                    .username(jwt.getSubject())
                    .roles(roles != null ? roles : Set.of())
                    .scopes(scopes != null ? scopes : Set.of())
                    .issuedAt(jwt.getIssuedAt())
                    .expiresAt(jwt.getExpiresAt())
                    .active(jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(Instant.now()))
                    .build();
        } catch (JwtException e) {
            log.error("Failed to get token info: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid token");
        }
    }

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Registering user with email: {}", request.getEmail());
        log.debug("Register request: email={}, firstName={}, lastName={}, role={}, clientId={}, companyName={}",
                request.getEmail(), request.getFirstName(), request.getLastName(),
                request.getRole(), request.getClientId(), request.getCompanyName());

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new DuplicateEmailException("Пользователь с таким email уже существует");
        }

        RoleType roleType = RoleType.DEFAULT;
        if (request.getRole() != null && !request.getRole().isBlank()) {
            try {
                roleType = RoleType.valueOf(request.getRole().trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Unknown role: " + request.getRole());
            }
        }

        com.trustflow.compliance_auth_service.domain.Role role = roleRepository.findByName(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not found"));

        String username = request.getEmail();
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        com.trustflow.compliance_auth_service.domain.User user = com.trustflow.compliance_auth_service.domain.User.builder()
                .username(username)
                .email(request.getEmail())
                .password(encodedPassword)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .isFirstLogin(true)
                .isSuperUser(roleType == RoleType.EXECUTIVE)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(java.util.Set.of(role))
                .build();

        userRepository.save(user);

        if (roleType == RoleType.EXECUTIVE) {
            if (request.getCompanyName() == null || request.getCompanyName().isBlank()) {
                throw new IllegalArgumentException("companyName is required when role is EXECUTIVE");
            }
            saveAllPermissionsForExecutive(user.getId());
            companyEventPublisher.publishCompanyCreated(
                    request.getCompanyName().trim(),
                    user.getId(),
                    roleType.name()
            );
        } else {
            saveEmptyPermissionsForUser(user.getId());
        }

        String clientId = request.getClientId() != null && !request.getClientId().isBlank()
                ? request.getClientId().trim()
                : "frontend-client";
        TokenResponse tokenResponse = authenticate(username, request.getPassword(), clientId);

        RegisterUserResponse userResponse = RegisterUserResponse.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(roleType.name())
                .isFirstLogin(user.getIsFirstLogin())
                .build();

        AuthTokens authTokens = AuthTokens.builder()
                .accessToken(tokenResponse.getAccessToken())
                .refreshToken(tokenResponse.getRefreshToken())
                .build();

        return AuthResponse.builder()
                .user(userResponse)
                .tokens(authTokens)
                .build();
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        String email = request.getEmail();
        String username = request.getUsername();
        String password = request.getPassword();
        String clientId = request.getClientId() != null ? request.getClientId() : "frontend-client";

        if (email == null && username == null) {
            throw new IllegalArgumentException("Either email or username must be provided");
        }

        String actualUsername;
        if (email != null) {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Неверный email или пароль"));
            actualUsername = user.getUsername();
        } else {
            actualUsername = username;
        }

        try {
            TokenResponse tokenResponse = authenticate(actualUsername, password, clientId);
            User user = userRepository.findByUsername(actualUsername)
                    .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Неверный email или пароль"));

            // Get user's role (first role)
            String role = user.getRoles().stream()
                    .findFirst()
                    .map(r -> r.getName().name())
                    .orElse("USER");

            String employeeId = cmsCompanyInfoClient.fetchEmployeeId(tokenResponse.getAccessToken());

            RegisterUserResponse userResponse = RegisterUserResponse.builder()
                    .id(user.getId().toString())
                    .email(user.getEmail())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .role(role)
                    .isFirstLogin(user.getIsFirstLogin())
                    .employeeId(employeeId)
                    .build();

            AuthTokens authTokens = AuthTokens.builder()
                    .accessToken(tokenResponse.getAccessToken())
                    .refreshToken(tokenResponse.getRefreshToken())
                    .build();

            return AuthResponse.builder()
                    .user(userResponse)
                    .tokens(authTokens)
                    .build();
        } catch (org.springframework.security.authentication.BadCredentialsException ex) {
            throw ex;
        } catch (org.springframework.security.core.AuthenticationException e) {
            throw new org.springframework.security.authentication.BadCredentialsException("Неверный email или пароль");
        }
    }

    @Override
    @Transactional
    public AdminLoginResponse adminLogin(LoginRequest request) {
        String email = request.getEmail();
        String username = request.getUsername();
        String password = request.getPassword();
        String clientId = request.getClientId() != null ? request.getClientId() : "frontend-client";

        if (email == null && username == null) {
            throw new IllegalArgumentException("Either email or username must be provided");
        }

        String actualUsername;
        if (email != null) {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Неверный email или пароль"));
            actualUsername = user.getUsername();
        } else {
            actualUsername = username;
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(actualUsername, password)
            );

            User user = userRepository.findByUsername(actualUsername)
                    .orElseThrow(() -> new org.springframework.security.authentication.BadCredentialsException("Неверный email или пароль"));

            if (!canAccessAdminPanel(user.getId())) {
                throw new AccessDeniedException("Недостаточно прав для входа в админ-панель");
            }

            TokenResponse adminTokens = issueAdminPanelTokens(authentication, clientId, user.getId());

            String role = user.getRoles().stream()
                    .findFirst()
                    .map(r -> r.getName().name())
                    .orElse("USER");

            String companyId = resolveCompanyIdForAdminLogin(user.getId(), adminTokens.getAccessToken());

            AdminLoginUserDto userDto = AdminLoginUserDto.builder()
                    .id(user.getId().toString())
                    .name(buildDisplayName(user))
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .email(user.getEmail())
                    .role(role)
                    .companyId(companyId)
                    .employeeId(cmsCompanyInfoClient.fetchEmployeeId(adminTokens.getAccessToken()))
                    .hasAdminAccess(true)
                    .build();

            return AdminLoginResponse.builder()
                    .accessToken(adminTokens.getAccessToken())
                    .refreshToken(adminTokens.getRefreshToken())
                    .companyId(companyId)
                    .user(userDto)
                    .build();
        } catch (org.springframework.security.authentication.BadCredentialsException ex) {
            throw ex;
        } catch (org.springframework.security.core.AuthenticationException e) {
            throw new org.springframework.security.authentication.BadCredentialsException("Неверный email или пароль");
        }
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(String username) {
        log.info("Revoking all tokens for user: {}", username);

        String sql = "DELETE FROM oauth2_authorization WHERE principal_name = ?";
        int deletedCount = jdbcTemplate.update(sql, username);

        log.info("Revoked {} token(s) for user: {}", deletedCount, username);
    }

    @Override
    public String getUserIdByEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required");
        }
        User user = userRepository.findByEmail(email.trim())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        return user.getId().toString();
    }

    @Override
    public RegisterUserResponse getEmployeeByUserId(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId is required");
        }
        log.debug("getEmployeeByUserId called with raw userId={}", userId);

        String normalizedUserId = normalizeUserId(userId);
        UUID userUuid;
        try {
            userUuid = UUID.fromString(normalizedUserId);
        } catch (IllegalArgumentException ex) {
            throw new UsernameNotFoundException("User not found with id: " + normalizedUserId);
        }

        User user = userRepository.findById(userUuid)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userUuid));

        String role = user.getRoles().stream()
                .findFirst()
                .map(r -> r.getName().name())
                .orElse("USER");

        RegisterUserResponse response = RegisterUserResponse.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(role)
                .isFirstLogin(user.getIsFirstLogin())
                .build();
        log.debug("getEmployeeByUserId success for userId={}", response.getId());
        return response;
    }

    private String normalizeUserId(String rawUserId) {
        String value = rawUserId.trim();
        if (value.startsWith("{") && value.endsWith("}")) {
            value = value.substring(1, value.length() - 1);
        }
        if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 1) {
            value = value.substring(1, value.length() - 1);
        }
        return value;
    }

    private TokenResponse issueAdminPanelTokens(Authentication authentication, String clientId, UUID userId) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client ID: " + clientId);
        }

        OAuth2TokenContext accessTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(buildAuthorizationServerContext())
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2AccessToken accessToken = generateAccessToken(accessTokenContext, registeredClient.getScopes());
        if (accessToken == null) {
            throw new IllegalStateException("Failed to generate access token");
        }

        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationServerContext(buildAuthorizationServerContext())
                .authorizationGrantType(new AuthorizationGrantType("password"))
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2RefreshToken refreshToken = (OAuth2RefreshToken) tokenGenerator.generate(refreshTokenContext);
        if (refreshToken == null) {
            throw new IllegalStateException("Failed to generate refresh token");
        }

        saveAdminAuthTokens(userId, clientId, accessToken, refreshToken);

        return TokenResponse.builder()
                .accessToken(accessToken.getTokenValue())
                .refreshToken(refreshToken.getTokenValue())
                .tokenType("Bearer")
                .expiresIn(accessToken.getExpiresAt() != null
                        ? accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond()
                        : 900L)
                .scope(String.join(" ", registeredClient.getScopes()))
                .build();
    }

    private void saveAdminAuthTokens(
            UUID userId,
            String clientId,
            OAuth2AccessToken accessToken,
            OAuth2RefreshToken refreshToken) {
        String sql = """
                INSERT INTO admin_auth_tokens (
                    id, user_id, client_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at
                ) VALUES (
                    gen_random_uuid(), ?, ?, ?, ?, ?, ?
                )
                """;

        Timestamp accessExpiresAt = accessToken.getExpiresAt() != null
                ? Timestamp.from(accessToken.getExpiresAt())
                : null;
        Timestamp refreshExpiresAt = refreshToken.getExpiresAt() != null
                ? Timestamp.from(refreshToken.getExpiresAt())
                : null;

        jdbcTemplate.update(
                sql,
                userId,
                clientId,
                accessToken.getTokenValue(),
                refreshToken.getTokenValue(),
                accessExpiresAt,
                refreshExpiresAt
        );
    }

    /** Доступ в админ-панель, если в {@code permissions.value} есть хотя бы один элемент. */
    private boolean canAccessAdminPanel(UUID userId) {
        String sql = """
                SELECT EXISTS (
                    SELECT 1
                    FROM permissions
                    WHERE user_id = ?
                      AND cardinality(value) > 0
                )
                """;
        Boolean ok = jdbcTemplate.queryForObject(sql, Boolean.class, userId);
        return Boolean.TRUE.equals(ok);
    }

    private String buildDisplayName(User user) {
        String firstName = user.getFirstName() != null ? user.getFirstName().trim() : "";
        String lastName = user.getLastName() != null ? user.getLastName().trim() : "";
        String fullName = (firstName + " " + lastName).trim();
        if (!fullName.isBlank()) {
            return fullName;
        }
        return user.getUsername();
    }

    private String resolveCompanyId(UUID userId) {
        try {
            return jdbcTemplate.queryForObject(
                    "SELECT company_id::text FROM users WHERE id = ?",
                    String.class,
                    userId
            );
        } catch (DataAccessException ex) {
            return null;
        }
    }

    /**
     * Сначала company_id из users; если пусто — из cms-company-info по access token, затем сохранение в БД.
     */
    private String resolveCompanyIdForAdminLogin(UUID userId, String accessToken) {
        String fromDb = resolveCompanyId(userId);
        if (fromDb != null && !fromDb.isBlank()) {
            return fromDb.trim();
        }
        String fromCms = cmsCompanyInfoClient.fetchCompanyIdByUserId(userId.toString(), "Bearer " + accessToken);
        if (fromCms == null || fromCms.isBlank()) {
            return null;
        }
        String trimmed = fromCms.trim();
        try {
            UUID companyUuid = UUID.fromString(trimmed);
            int updated = jdbcTemplate.update(
                    "UPDATE users SET company_id = ? WHERE id = ?",
                    companyUuid,
                    userId
            );
            log.info("resolveCompanyIdForAdminLogin: persisted company_id from CMS userId={}, companyId={}, rowsUpdated={}",
                    userId, companyUuid, updated);
        } catch (IllegalArgumentException ex) {
            log.warn("resolveCompanyIdForAdminLogin: CMS returned non-UUID company id, not persisting userId={}, value={}",
                    userId, trimmed);
        }
        return trimmed;
    }

    private AuthorizationServerContext buildAuthorizationServerContext() {
        return new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return authorizationServerSettings.getIssuer();
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return authorizationServerSettings;
            }
        };
    }

    private void saveAllPermissionsForExecutive(UUID userId) {
        String allPermissionsAsArray = Arrays.stream(PermissionValueType.values())
                .map(Enum::name)
                .collect(Collectors.joining(",", "{", "}"));

        String sql = """
                INSERT INTO permissions (id, user_id, value)
                VALUES (gen_random_uuid(), ?, ?::permission_value_enum[])
                """;
        jdbcTemplate.update(sql, userId, allPermissionsAsArray);
    }

    private void saveEmptyPermissionsForUser(UUID userId) {
        String sql = """
                INSERT INTO permissions (id, user_id, value)
                VALUES (gen_random_uuid(), ?, '{}'::permission_value_enum[])
                """;
        jdbcTemplate.update(sql, userId);
    }

    private OAuth2AccessToken generateAccessToken(
            OAuth2TokenContext tokenContext,
            Set<String> fallbackScopes) {
        Object generatedToken = tokenGenerator.generate(tokenContext);
        if (generatedToken == null) {
            return null;
        }

        if (generatedToken instanceof OAuth2AccessToken oauth2AccessToken) {
            return oauth2AccessToken;
        }

        if (generatedToken instanceof Jwt jwt) {
            Set<String> tokenScopes = resolveScopes(jwt.getClaims(), fallbackScopes);
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(),
                    jwt.getIssuedAt(),
                    jwt.getExpiresAt(),
                    tokenScopes
            );
        }

        throw new IllegalStateException("Unsupported access token type: " + generatedToken.getClass().getName());
    }

    private Set<String> resolveScopes(Map<String, Object> claims, Set<String> fallbackScopes) {
        Object scopeClaim = claims.get("scope");
        if (scopeClaim instanceof String scopeString) {
            return Set.of(scopeString.split(" "));
        }
        if (scopeClaim instanceof Iterable<?> iterable) {
            return java.util.stream.StreamSupport.stream(iterable.spliterator(), false)
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .collect(Collectors.toSet());
        }
        return fallbackScopes;
    }

}
