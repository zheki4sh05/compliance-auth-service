package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.domain.User;
import com.trustflow.compliance_auth_service.domain.enums.PermissionValueType;
import com.trustflow.compliance_auth_service.dto.AccessPermissionsDto;
import com.trustflow.compliance_auth_service.dto.PermissionAccessCheckResponseDto;
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
    private static final String ACCESS_PERMIT = "permit";
    private static final String ACCESS_DENIED = "denied";

    private final JdbcTemplate jdbcTemplate;
    private final UserRepository userRepository;
    private final CmsCompanyInfoClient cmsCompanyInfoClient;

    @Override
    @Transactional(readOnly = true)
    public AccessPermissionsDto getUserAccessPermissions(UUID userId, String companyId) {
        log.info("getUserAccessPermissions: start targetUserId={}, companyId={}", userId, companyId);

        UUID currentUserId = resolveCurrentAuthenticatedUserId();

        ensureUserExists(userId);
        log.info("getUserAccessPermissions: ensureUserExists done targetUserId={}", userId);

        ensureCompanyScope(currentUserId, userId, companyId);
        log.info(
                "getUserAccessPermissions: ensureCompanyScope done currentUserId={}, targetUserId={}, companyId={}",
                currentUserId,
                userId,
                companyId
        );

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

        log.info(
                "getUserAccessPermissions: loaded {} distinct permission(s) from DB for targetUserId={}",
                permissions.size(),
                userId
        );
        log.debug("getUserAccessPermissions: permissions list for targetUserId={}: {}", userId, permissions);

        AccessPermissionsDto result = AccessPermissionsDto.builder()
                .accessPermissions(permissions)
                .build();

        log.info(
                "getUserAccessPermissions: complete targetUserId={}, companyId={}, permissionCount={}",
                userId,
                companyId,
                permissions.size()
        );
        return result;
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

    @Override
    @Transactional(readOnly = true)
    public PermissionAccessCheckResponseDto checkUserPermissionAccess(UUID userId, String permission) {
        if (permission == null || permission.isBlank()) {
            return PermissionAccessCheckResponseDto.builder()
                    .access(ACCESS_DENIED)
                    .build();
        }

        PermissionValueType requestedPermission;
        try {
            requestedPermission = PermissionValueType.valueOf(permission.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return PermissionAccessCheckResponseDto.builder()
                    .access(ACCESS_DENIED)
                    .build();
        }

        String sql = """
                SELECT EXISTS (
                    SELECT 1
                    FROM permissions
                    WHERE user_id = ?
                      AND value @> ARRAY[?::permission_value_enum]
                )
                """;

        Boolean hasPermission = jdbcTemplate.queryForObject(sql, Boolean.class, userId, requestedPermission.name());
        String access = Boolean.TRUE.equals(hasPermission) ? ACCESS_PERMIT : ACCESS_DENIED;

        return PermissionAccessCheckResponseDto.builder()
                .access(access)
                .build();
    }

    /** Изменение прав (PUT /access) — только с EDIT_USERS. */
    private UUID ensureCurrentUserCanManagePermissions() {
        UUID currentUserId = resolveCurrentAuthenticatedUserId();
        ensurePrincipalHasPermission(
                currentUserId,
                PermissionValueType.EDIT_USERS,
                "Permission EDIT_USERS is required"
        );
        log.info("ensureCurrentUserCanManagePermissions: complete currentUserId={}", currentUserId);
        return currentUserId;
    }

    private UUID resolveCurrentAuthenticatedUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("resolveCurrentAuthenticatedUserId: no authenticated user");
            throw new AccessDeniedException("Authentication required");
        }

        String username = authentication.getName();
        log.debug("resolveCurrentAuthenticatedUserId: principal username={}", username);
        return userRepository.findByUsername(username)
                .map(User::getId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }

    private void ensurePrincipalHasPermission(UUID principalUserId, PermissionValueType permission, String denialMessage) {
        String sql = """
                SELECT EXISTS (
                    SELECT 1
                    FROM permissions
                    WHERE user_id = ?
                      AND value @> ARRAY[?]::permission_value_enum[]
                )
                """;

        Boolean hasPermission = jdbcTemplate.queryForObject(sql, Boolean.class, principalUserId, permission.name());
        log.debug(
                "ensurePrincipalHasPermission: principalUserId={}, permission={}, ok={}",
                principalUserId,
                permission,
                hasPermission
        );
        if (!Boolean.TRUE.equals(hasPermission)) {
            log.warn(
                    "ensurePrincipalHasPermission: denied principalUserId={}, missing {}",
                    principalUserId,
                    permission
            );
            throw new AccessDeniedException(denialMessage);
        }
    }

    private void ensureUserExists(UUID userId) {
        log.debug("ensureUserExists: start userId={}", userId);
        if (userRepository.findById(userId).isEmpty()) {
            log.warn("ensureUserExists: user not found userId={}", userId);
            throw new UsernameNotFoundException("User not found with id: " + userId);
        }
        log.info("ensureUserExists: complete userId={} exists", userId);
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
        log.info(
                "ensureCompanyScope: start currentUserId={}, targetUserId={}, companyIdHeader={}",
                currentUserId,
                targetUserId,
                companyId
        );
        if (companyId == null || companyId.isBlank()) {
            log.warn("ensureCompanyScope: companyId header missing");
            throw new IllegalArgumentException("companyId header is required");
        }
        String normalizedCompanyId = companyId.trim();

        String authorizationHeader = resolveAuthorizationHeader();
        String currentUserCompanyId = cmsCompanyInfoClient.fetchCompanyIdByUserId(currentUserId.toString(), authorizationHeader);
        String targetUserCompanyId = cmsCompanyInfoClient.fetchCompanyIdByUserId(targetUserId.toString(), authorizationHeader);

        log.info(
                "ensureCompanyScope: resolved companyIds — header={}, currentUserCompanyId={}, targetUserCompanyId={}",
                normalizedCompanyId,
                currentUserCompanyId,
                targetUserCompanyId
        );

        boolean isInCompanyScope = normalizedCompanyId.equals(currentUserCompanyId)
                && normalizedCompanyId.equals(targetUserCompanyId);

        if (!isInCompanyScope) {
            log.warn(
                    "ensureCompanyScope: denied — scope mismatch header={}, currentUser={}, target={}",
                    normalizedCompanyId,
                    currentUserCompanyId,
                    targetUserCompanyId
            );
            throw new AccessDeniedException("Permission management is allowed only within the requested company scope");
        }
        log.info(
                "ensureCompanyScope: complete currentUserId={}, targetUserId={}, companyId={}",
                currentUserId,
                targetUserId,
                normalizedCompanyId
        );
    }

    private String resolveAuthorizationHeader() {
        log.debug("resolveAuthorizationHeader: start");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("resolveAuthorizationHeader: no authenticated user");
            throw new AccessDeniedException("Authentication required");
        }

        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            String header = "Bearer " + jwtAuthenticationToken.getToken().getTokenValue();
            log.info("resolveAuthorizationHeader: complete source=jwt tokenLength={}", header.length());
            return header;
        }
        Object credentials = authentication.getCredentials();
        if (credentials instanceof String tokenString && !tokenString.isBlank()) {
            String header = tokenString.startsWith("Bearer ") ? tokenString : "Bearer " + tokenString;
            log.info("resolveAuthorizationHeader: complete source=credentials headerLength={}", header.length());
            return header;
        }

        log.warn("resolveAuthorizationHeader: no bearer token in authentication");
        throw new AccessDeniedException("Authentication token is required");
    }
}
