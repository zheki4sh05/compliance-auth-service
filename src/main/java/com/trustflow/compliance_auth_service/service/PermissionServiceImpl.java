package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.domain.enums.PermissionValueType;
import com.trustflow.compliance_auth_service.dto.AccessPermissionsDto;
import com.trustflow.compliance_auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.PreparedStatement;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {

    private final JdbcTemplate jdbcTemplate;
    private final UserRepository userRepository;
    private final CmsCompanyInfoClient cmsCompanyInfoClient;

    @Override
    @Transactional(readOnly = true)
    public AccessPermissionsDto getUserAccessPermissions(UUID userId, String companyId) {
        UUID currentUserId = ensureCurrentUserCanManagePermissions();
        ensureUserExists(userId);
        ensureCompanyScope(currentUserId, userId, companyId);

        String sql = """
                SELECT DISTINCT unnest(value)::text AS permission
                FROM permissions
                WHERE user_id = ?
                ORDER BY permission
                """;

        List<String> permissions = jdbcTemplate.query(
                sql,
                (rs, rowNum) -> rs.getString("permission").toLowerCase(Locale.ROOT),
                userId
        );

        return AccessPermissionsDto.builder()
                .accessPermissions(permissions)
                .build();
    }

    @Override
    @Transactional
    public AccessPermissionsDto updateUserAccessPermissions(UUID userId, String companyId, AccessPermissionsDto accessPermissionsDto) {
        UUID currentUserId = ensureCurrentUserCanManagePermissions();
        ensureUserExists(userId);
        ensureCompanyScope(currentUserId, userId, companyId);

        List<String> requestedPermissions = accessPermissionsDto != null
                ? accessPermissionsDto.getAccessPermissions()
                : List.of();

        Set<PermissionValueType> normalizedPermissions = normalizePermissions(requestedPermissions);
        savePermissions(userId, normalizedPermissions);

        List<String> responsePermissions = normalizedPermissions.stream()
                .map(permission -> permission.name().toLowerCase(Locale.ROOT))
                .toList();

        return AccessPermissionsDto.builder()
                .accessPermissions(responsePermissions)
                .build();
    }

    private UUID ensureCurrentUserCanManagePermissions() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }

        String username = authentication.getName();
        UUID currentUserId = userRepository.findByUsername(username)
                .map(user -> user.getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        String sql = """
                SELECT EXISTS (
                    SELECT 1
                    FROM permissions
                    WHERE user_id = ?
                      AND value @> ARRAY['EDIT_USERS']::permission_value_enum[]
                )
                """;

        Boolean hasEditUsersPermission = jdbcTemplate.queryForObject(sql, Boolean.class, currentUserId);
        if (!Boolean.TRUE.equals(hasEditUsersPermission)) {
            throw new AccessDeniedException("Permission EDIT_USERS is required");
        }

        return currentUserId;
    }

    private void ensureUserExists(UUID userId) {
        if (userRepository.findById(userId).isEmpty()) {
            throw new UsernameNotFoundException("User not found with id: " + userId);
        }
    }

    private Set<PermissionValueType> normalizePermissions(List<String> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            return Set.of();
        }

        Set<PermissionValueType> normalized = new LinkedHashSet<>();
        for (String permission : permissions) {
            if (permission == null || permission.isBlank()) {
                throw new IllegalArgumentException("Permission value must not be blank");
            }

            String enumName = permission.trim().toUpperCase(Locale.ROOT);
            try {
                normalized.add(PermissionValueType.valueOf(enumName));
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Unknown permission: " + permission);
            }
        }

        return normalized;
    }

    private void savePermissions(UUID userId, Set<PermissionValueType> permissions) {
        String deleteSql = "DELETE FROM permissions WHERE user_id = ?";
        jdbcTemplate.update(deleteSql, userId);

        List<String> enumValues = permissions.stream()
                .map(Enum::name)
                .toList();

        String insertSql = """
                INSERT INTO permissions (id, user_id, value)
                VALUES (gen_random_uuid(), ?, ?::permission_value_enum[])
                """;

        jdbcTemplate.update(connection -> {
            PreparedStatement statement = connection.prepareStatement(insertSql);
            statement.setObject(1, userId);
            java.sql.Array permissionArray = connection.createArrayOf("permission_value_enum", enumValues.toArray(new String[0]));
            statement.setArray(2, permissionArray);

            return statement;
        });
        log.info("Updated permissions for user {}", userId);
    }

    private void ensureCompanyScope(UUID currentUserId, UUID targetUserId, String companyId) {
        if (companyId == null || companyId.isBlank()) {
            throw new IllegalArgumentException("companyId header is required");
        }
        String normalizedCompanyId = companyId.trim();

        String authorizationHeader = resolveAuthorizationHeader();
        String currentUserCompanyId = cmsCompanyInfoClient.fetchCompanyIdByUserId(currentUserId.toString(), authorizationHeader);
        String targetUserCompanyId = cmsCompanyInfoClient.fetchCompanyIdByUserId(targetUserId.toString(), authorizationHeader);

        boolean isInCompanyScope = normalizedCompanyId.equals(currentUserCompanyId)
                && normalizedCompanyId.equals(targetUserCompanyId);

        if (!isInCompanyScope) {
            throw new AccessDeniedException("Permission management is allowed only within the requested company scope");
        }
    }

    private String resolveAuthorizationHeader() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }

        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            return "Bearer " + jwtAuthenticationToken.getToken().getTokenValue();
        }
        Object credentials = authentication.getCredentials();
        if (credentials instanceof String tokenString && !tokenString.isBlank()) {
            return tokenString.startsWith("Bearer ") ? tokenString : "Bearer " + tokenString;
        }

        throw new AccessDeniedException("Authentication token is required");
    }
}
