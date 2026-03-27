package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.dto.*;
import com.trustflow.compliance_auth_service.exception.DuplicateEmailException;
import com.trustflow.compliance_auth_service.repository.RoleRepository;
import com.trustflow.compliance_auth_service.repository.UserRepository;
import com.trustflow.compliance_auth_service.domain.Role;
import com.trustflow.compliance_auth_service.domain.User;
import com.trustflow.compliance_auth_service.domain.enums.RoleType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
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
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(registeredClient.getScopes())
                .build();

        OAuth2AccessToken accessToken = (OAuth2AccessToken) tokenGenerator.generate(accessTokenContext);
        if (accessToken == null) {
            throw new IllegalStateException("Failed to generate access token");
        }

        // Генерация Refresh Token
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
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
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .build();

        OAuth2AccessToken newAccessToken = (OAuth2AccessToken) tokenGenerator.generate(accessTokenContext);
        if (newAccessToken == null) {
            throw new IllegalStateException("Failed to generate new access token");
        }

        // Генерация нового Refresh Token
        OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
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

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new com.trustflow.compliance_auth_service.exception.DuplicateEmailException("Пользователь с таким email уже существует");
        }

        com.trustflow.compliance_auth_service.domain.Role role = roleRepository.findByName(RoleType.DEFAULT)
                .orElseThrow(() -> new IllegalStateException("Default role DEFAULT not found"));

        String username = request.getEmail();
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        com.trustflow.compliance_auth_service.domain.User user = com.trustflow.compliance_auth_service.domain.User.builder()
                .username(username)
                .email(request.getEmail())
                .password(encodedPassword)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .departmentId(request.getDepartmentId())
                .isFirstLogin(true)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(java.util.Set.of(role))
                .build();

        userRepository.save(user);

        String clientId = "monitoring-service";
        TokenResponse tokenResponse = authenticate(username, request.getPassword(), clientId);

        RegisterUserResponse userResponse = RegisterUserResponse.builder()
                .id(user.getId().toString())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role("DEFAULT")
                .departmentId(user.getDepartmentId())
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
        String clientId = request.getClientId() != null ? request.getClientId() : "monitoring-service";

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

            RegisterUserResponse userResponse = RegisterUserResponse.builder()
                    .id(user.getId().toString())
                    .email(user.getEmail())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .role(role)
                    .departmentId(user.getDepartmentId())
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
}
