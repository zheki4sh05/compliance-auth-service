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
        UUID currentUserId = resolveAuthenticatedUserId();
        ensureUserHasPermission(currentUserId, PermissionValueType.VIEW_USERS_PAGE, "Недостаточно прав для просмотра пользователей");

        UUID parsedCompanyId = parseCompanyId(companyId);
        log.info("Fetching users for companyId={}", parsedCompanyId);

        List<User> users = userRepository.findAllByCompanyId(parsedCompanyId);
        if (users.isEmpty()) {
            return CompanyUsersResponseDto.builder()
                    .items(List.of())
                    .build();
        }

        Map<UUID, List<String>> accessPermissionsByUserId = loadAccessPermissions(users);
        List<CompanyUserItemDto> items = users.stream()
                .map(user -> mapToCompanyUserItemDto(
                        user,
                        accessPermissionsByUserId.getOrDefault(user.getId(), List.of())
                ))
                .toList();

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
    public UserDto update(UUID id, UserDto userDto) {
        log.info("Updating user with id: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        // Обновление полей
        if (userDto.getEmail() != null && !userDto.getEmail().equals(user.getEmail())) {
            if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
                throw new IllegalArgumentException("Email already in use: " + userDto.getEmail());
            }
            user.setEmail(userDto.getEmail());
        }

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        if (userDto.getEnabled() != null) {
            user.setEnabled(userDto.getEnabled());
        }

        // Обновление ролей
        if (userDto.getRoles() != null && !userDto.getRoles().isEmpty()) {
            Set<Role> roles = userDto.getRoles().stream()
                    .map(roleType -> roleRepository.findByName(roleType)
                            .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleType)))
                    .collect(Collectors.toSet());
            user.setRoles(roles);
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
        return CompanyUserItemDto.builder()
                .id(user.getId().toString())
                .name(buildDisplayName(user))
                .email(user.getEmail())
                .status(Boolean.TRUE.equals(user.getEnabled()) ? "active" : "blocked")
                .jobTitle(resolveJobTitle(user.getRoles()))
                .accessPermissions(accessPermissions)
                .createdAt(formatCreatedAt(user.getCreatedAt()))
                .build();
    }

    private Map<UUID, List<String>> loadAccessPermissions(List<User> users) {
        List<UUID> userIds = users.stream()
                .map(User::getId)
                .toList();
        if (userIds.isEmpty()) {
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

        return result;
    }

    private UUID parseCompanyId(String companyId) {
        if (companyId == null || companyId.isBlank()) {
            throw new IllegalArgumentException("companyId is required");
        }
        try {
            return UUID.fromString(companyId.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Некорректный companyId");
        }
    }

    private String resolveJobTitle(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return "employee";
        }
        if (roles.stream().anyMatch(role -> role.getName() == RoleType.EXECUTIVE)) {
            return "top_management";
        }
        if (roles.stream().anyMatch(role -> role.getName() == RoleType.SUPERVISOR)) {
            return "middle_management";
        }
        return "employee";
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
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getName())) {
            throw new AuthenticationCredentialsNotFoundException("Требуется вход");
        }
        return userRepository.findByUsername(authentication.getName())
                .map(User::getId)
                .orElseThrow(() -> new AuthenticationCredentialsNotFoundException("Требуется вход"));
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

        if (!Boolean.TRUE.equals(hasPermission)) {
            throw new AccessDeniedException(errorMessage);
        }
    }

}

