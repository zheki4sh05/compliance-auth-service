package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.domain.*;
import com.trustflow.compliance_auth_service.domain.enums.*;
import com.trustflow.compliance_auth_service.dto.*;
import com.trustflow.compliance_auth_service.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private static final DateTimeFormatter LIST_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JdbcTemplate jdbcTemplate;
    private final CmsCompanyInfoClient cmsCompanyInfoClient;

    @Override
    @Transactional(readOnly = true)
    public CompanyUsersResponseDto findAllByCompanyId(String companyId) {
        log.info("findAllByCompanyId: start, companyId={}", companyId);
        UUID currentUserId = resolveAuthenticatedUserId();
        log.info("findAllByCompanyId: resolved currentUserId={}", currentUserId);
        ensureUserHasPermission(currentUserId, PermissionValueType.VIEW_USERS_PAGE, "Недостаточно прав для просмотра пользователей");
        log.info("findAllByCompanyId: permission check passed, userId={}, permission={}", currentUserId, PermissionValueType.VIEW_USERS_PAGE);

        UUID parsedCompanyId = parseCompanyId(companyId);
        log.info("findAllByCompanyId: parsed companyId={}, rawCompanyId={}", parsedCompanyId, companyId);

        List<User> users = userRepository.findAllByCompanyId(parsedCompanyId);
        log.info("findAllByCompanyId: users fetched, companyId={}, usersCount={}", parsedCompanyId, users.size());
        log.debug("findAllByCompanyId: fetched userIds={}", users.stream().map(User::getId).toList());
        if (users.isEmpty()) {
            log.info("findAllByCompanyId: no users found, companyId={}", parsedCompanyId);
            return CompanyUsersResponseDto.builder()
                    .items(List.of())
                    .build();
        }

        Map<UUID, List<String>> accessPermissionsByUserId = loadAccessPermissions(users);
        log.info("findAllByCompanyId: permissions loaded, usersWithPermissionsCount={}", accessPermissionsByUserId.size());
        List<CompanyUserItemDto> items = users.stream()
                .map(user -> mapToCompanyUserItemDto(
                        user,
                        accessPermissionsByUserId.getOrDefault(user.getId(), List.of())
                ))
                .toList();
        log.debug("findAllByCompanyId: mapped items={}", items);
        log.info("findAllByCompanyId: complete, companyId={}, itemsCount={}", parsedCompanyId, items.size());

        return CompanyUsersResponseDto.builder()
                .items(items)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto findById(UUID id) {
        log.info("Fetching user by id: {}", id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));
        return mapToDto(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserBasicInfoDto findBasicInfoById(UUID id) {
        log.info("Fetching basic user info by id: {}", id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        return UserBasicInfoDto.builder()
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto findByUsername(String username) {
        log.info("Fetching user by username: {}", username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return mapToDto(user);
    }

    @Override
    @Transactional
    public UserDto create(UserDto userDto) {
        log.info("Creating new user: {}", userDto.getUsername());

        // Проверка на существование пользователя
        if (userRepository.findByUsername(userDto.getUsername()).isPresent()) {
            throw new IllegalArgumentException("User already exists with username: " + userDto.getUsername());
        }

        if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("User already exists with email: " + userDto.getEmail());
        }

        // Создание пользователя
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .email(userDto.getEmail())
                .isSuperUser(false)
                .enabled(userDto.getEnabled() != null ? userDto.getEnabled() : true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        // Установка ролей
        if (userDto.getRoles() != null && !userDto.getRoles().isEmpty()) {
            Set<Role> roles = userDto.getRoles().stream()
                    .map(roleType -> roleRepository.findByName(roleType)
                            .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleType)))
                    .collect(Collectors.toSet());
            user.setRoles(roles);
        } else {
            // По умолчанию роль DEFAULT
            Role defaultRole = roleRepository.findByName(RoleType.DEFAULT)
                    .orElseThrow(() -> new IllegalStateException("Default role DEFAULT not found"));
            user.setRoles(Set.of(defaultRole));
        }

        User savedUser = userRepository.save(user);
        log.info("Successfully created user: {}", savedUser.getUsername());

        return mapToDto(savedUser);
    }

    @Override
    @Transactional
    public UserDto update(UUID id, UserProfileUpdateRequestDto userProfileUpdateRequestDto) {
        log.info("Updating user with id: {}", id);

        UUID authenticatedUserId = resolveAuthenticatedUserId();
        if (!authenticatedUserId.equals(id)) {
            throw new AccessDeniedException("Можно изменять только собственный профиль");
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        if (userProfileUpdateRequestDto.getEmail() != null) {
            String normalizedEmail = userProfileUpdateRequestDto.getEmail().trim();
            if (normalizedEmail.isBlank()) {
                throw new IllegalArgumentException("Email must not be blank");
            }

            if (!normalizedEmail.equals(user.getEmail())) {
                userRepository.findByEmail(normalizedEmail)
                        .filter(existingUser -> !existingUser.getId().equals(id))
                        .ifPresent(existingUser -> {
                            throw new IllegalArgumentException("Email already in use: " + normalizedEmail);
                        });
                user.setEmail(normalizedEmail);
            }
        }

        if (userProfileUpdateRequestDto.getFirstName() != null) {
            String normalizedFirstName = userProfileUpdateRequestDto.getFirstName().trim();
            user.setFirstName(normalizedFirstName.isBlank() ? null : normalizedFirstName);
        }

        if (userProfileUpdateRequestDto.getLastName() != null) {
            String normalizedLastName = userProfileUpdateRequestDto.getLastName().trim();
            user.setLastName(normalizedLastName.isBlank() ? null : normalizedLastName);
        }

        User updatedUser = userRepository.save(user);
        log.info("Successfully updated user: {}", updatedUser.getUsername());

        return mapToDto(updatedUser);
    }

    @Override
    @Transactional
    public UserStatusDto updateUserStatus(UUID id, String companyId, UserStatusDto userStatusDto) {
        if (userStatusDto == null || userStatusDto.getStatus() == null || userStatusDto.getStatus().isBlank()) {
            throw new IllegalArgumentException("Некорректный статус");
        }

        Boolean enabled = switch (userStatusDto.getStatus().trim().toLowerCase(Locale.ROOT)) {
            case "active" -> true;
            case "blocked" -> false;
            default -> throw new IllegalArgumentException("Некорректный статус");
        };

        User targetUser = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

        UUID currentUserId = resolveAuthenticatedUserId();
        ensureCompanyAndPermissionScope(currentUserId, targetUser.getId(), companyId);

        targetUser.setEnabled(enabled);
        userRepository.save(targetUser);

        return UserStatusDto.builder()
                .status(enabled ? "active" : "blocked")
                .build();
    }

    @Override
    @Transactional
    public void delete(UUID id) {
        log.info("Deleting user with id: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        userRepository.delete(user);
        log.info("Successfully deleted user: {}", user.getUsername());
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user found");
        }

        String username = authentication.getName();
        return findByUsername(username);
    }

    @Override
    @Transactional(readOnly = true)
    public AdminLoginUserDto getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user found");
        }

        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + authentication.getName()));

        String role = user.getRoles().stream()
                .findFirst()
                .map(r -> r.getName().name())
                .orElse("USER");

        return AdminLoginUserDto.builder()
                .id(user.getId().toString())
                .name(buildDisplayName(user))
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .role(role)
                .companyId(resolveCompanyId(user.getId()))
                .employeeId(resolveEmployeeId(authentication))
                .build();
    }

    // Helper method для маппинга Entity -> DTO
    private UserDto mapToDto(User user) {
        UserDto dto = new UserDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setEnabled(user.getEnabled());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());

        if (user.getRoles() != null) {
            dto.setRoles(user.getRoles().stream()
                    .map(Role::getName)
                    .collect(Collectors.toSet()));
        }

        return dto;
    }

    private CompanyUserItemDto mapToCompanyUserItemDto(User user, List<String> accessPermissions) {
        CompanyUserItemDto item = CompanyUserItemDto.builder()
                .id(user.getId().toString())
                .name(buildDisplayName(user))
                .email(user.getEmail())
                .status(Boolean.TRUE.equals(user.getEnabled()) ? "active" : "blocked")
                .jobTitle(resolveJobTitle(user.getRoles()))
                .accessPermissions(accessPermissions)
                .createdAt(formatCreatedAt(user.getCreatedAt()))
                .build();
        log.debug("mapToCompanyUserItemDto: mapped userId={}, status={}, jobTitle={}, permissionsCount={}",
                user.getId(),
                item.getStatus(),
                item.getJobTitle(),
                accessPermissions != null ? accessPermissions.size() : 0);
        return item;
    }

    private Map<UUID, List<String>> loadAccessPermissions(List<User> users) {
        log.debug("loadAccessPermissions: start, usersCount={}", users.size());
        List<UUID> userIds = users.stream()
                .map(User::getId)
                .toList();
        if (userIds.isEmpty()) {
            log.debug("loadAccessPermissions: no userIds provided");
            return Map.of();
        }

        String sql = """
                SELECT p.user_id, unnest(p.value)::text AS permission
                FROM permissions p
                WHERE p.user_id = ANY (?::uuid[])
                ORDER BY p.user_id, permission
                """;

        Map<UUID, List<String>> result = new HashMap<>();
        jdbcTemplate.query(connection -> {
            var statement = connection.prepareStatement(sql);
            java.sql.Array userIdArray = connection.createArrayOf("uuid", userIds.toArray());
            statement.setArray(1, userIdArray);
            return statement;
        }, rs -> {
            UUID userId = rs.getObject("user_id", UUID.class);
            String permission = rs.getString("permission");
            result.computeIfAbsent(userId, ignored -> new ArrayList<>())
                    .add(permission.toLowerCase(Locale.ROOT));
        });

        log.debug("loadAccessPermissions: complete, userIdsCount={}, result={}", userIds.size(), result);
        return result;
    }

    private UUID parseCompanyId(String companyId) {
        log.debug("parseCompanyId: input companyId={}", companyId);
        if (companyId == null || companyId.isBlank()) {
            log.warn("parseCompanyId: companyId is blank");
            throw new IllegalArgumentException("companyId is required");
        }
        try {
            UUID parsed = UUID.fromString(companyId.trim());
            log.debug("parseCompanyId: parsed companyId={}", parsed);
            return parsed;
        } catch (IllegalArgumentException ex) {
            log.warn("parseCompanyId: invalid companyId={}, error={}", companyId, ex.getMessage());
            throw new IllegalArgumentException("Некорректный companyId");
        }
    }

    private String resolveJobTitle(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return "manager";
        }
        if (roles.stream().anyMatch(role -> role.getName() == RoleType.EXECUTIVE)) {
            return "executive";
        }
        if (roles.stream().anyMatch(role -> role.getName() == RoleType.SUPERVISOR)) {
            return "supervisor";
        }
        if (roles.stream().anyMatch(role -> role.getName() == RoleType.MANAGER)) {
            return "manager";
        }
        return "manager";
    }

    private String formatCreatedAt(LocalDateTime createdAt) {
        if (createdAt == null) {
            return null;
        }
        return createdAt.format(LIST_DATE_FORMATTER);
    }




    private List<String> getPermissionsByRole(Set<Role> roles) {
        // Мапинг ролей на права доступа
        if (roles.stream().anyMatch(r -> r.getName() == RoleType.EXECUTIVE)) {
            return List.of("VIEW_CASES", "EDIT_CASES", "DELETE_CASES", "ASSIGN_TASKS",
                    "MANAGE_USERS", "VIEW_REPORTS", "MANAGE_SETTINGS");
        } else if (roles.stream().anyMatch(r -> r.getName() == RoleType.SUPERVISOR)) {
            return List.of("VIEW_CASES", "EDIT_CASES", "ASSIGN_TASKS",
                    "VIEW_REPORTS", "MANAGE_TEAM");
        } else {
            return List.of("VIEW_CASES", "EDIT_CASES", "ASSIGN_TASKS");
        }
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

    private String resolveEmployeeId(Authentication authentication) {
        String accessToken = extractAccessToken(authentication);
        if (accessToken == null || accessToken.isBlank()) {
            return null;
        }
        return cmsCompanyInfoClient.fetchEmployeeId(accessToken);
    }

    private String extractAccessToken(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            return jwtAuthenticationToken.getToken().getTokenValue();
        }
        Object credentials = authentication.getCredentials();
        if (credentials instanceof String tokenString) {
            return tokenString;
        }
        return null;
    }

    private UUID resolveAuthenticatedUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String authName = authentication != null ? authentication.getName() : null;
        log.debug("resolveAuthenticatedUserId: authenticationName={}", authName);
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getName())) {
            log.warn("resolveAuthenticatedUserId: user is not authenticated");
            throw new AuthenticationCredentialsNotFoundException("Требуется вход");
        }
        UUID resolvedUserId = userRepository.findByUsername(authentication.getName())
                .map(User::getId)
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException("Требуется вход"));
        log.debug("resolveAuthenticatedUserId: resolved userId={}", resolvedUserId);
        return resolvedUserId;
    }

    private void ensureCompanyAndPermissionScope(UUID currentUserId, UUID targetUserId, String companyId) {
        if (companyId == null || companyId.isBlank()) {
            throw new IllegalArgumentException("companyId is required");
        }

        String normalizedCompanyId = companyId.trim();
        String authorizationHeader = resolveAuthorizationHeader();
        String currentUserCompanyId = cmsCompanyInfoClient.fetchCompanyIdByUserId(currentUserId.toString(), authorizationHeader);
        String targetUserCompanyId = cmsCompanyInfoClient.fetchCompanyIdByUserId(targetUserId.toString(), authorizationHeader);

        boolean isInCompanyScope = normalizedCompanyId.equals(currentUserCompanyId)
                && normalizedCompanyId.equals(targetUserCompanyId);
        if (!isInCompanyScope) {
            throw new AccessDeniedException("Недостаточно прав для изменения статуса пользователя");
        }

        ensureUserHasPermission(currentUserId, PermissionValueType.EDIT_USERS, "Недостаточно прав для изменения статуса пользователя");
    }

    private String resolveAuthorizationHeader() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String accessToken = extractAccessToken(authentication);
        if (accessToken == null || accessToken.isBlank()) {
            throw new AuthenticationCredentialsNotFoundException("Требуется вход");
        }
        return accessToken.startsWith("Bearer ") ? accessToken : "Bearer " + accessToken;
    }

    private void ensureUserHasPermission(UUID userId, PermissionValueType permission, String errorMessage) {
        log.debug("ensureUserHasPermission: checking userId={}, permission={}", userId, permission);
        String sql = """
                SELECT EXISTS (
                    SELECT 1
                    FROM permissions p
                    WHERE p.user_id = ?
                      AND p.value @> ARRAY[?]::permission_value_enum[]
                )
                """;

        Boolean hasPermission = jdbcTemplate.queryForObject(
                sql,
                Boolean.class,
                userId,
                permission.name()
        );

        log.debug("ensureUserHasPermission: result userId={}, permission={}, hasPermission={}", userId, permission, hasPermission);
        if (!Boolean.TRUE.equals(hasPermission)) {
            log.warn("ensureUserHasPermission: access denied userId={}, permission={}", userId, permission);
            throw new AccessDeniedException(errorMessage);
        }
    }

}

