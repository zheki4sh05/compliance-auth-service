package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.dto.AccessPermissionsDto;
import com.trustflow.compliance_auth_service.dto.PermissionAccessCheckResponseDto;

import java.util.UUID;

public interface PermissionService {
    AccessPermissionsDto getUserAccessPermissions(UUID userId, String companyId);
    AccessPermissionsDto updateUserAccessPermissions(UUID userId, String companyId, AccessPermissionsDto accessPermissionsDto);
    PermissionAccessCheckResponseDto checkUserPermissionAccess(UUID userId, String permission);
}
