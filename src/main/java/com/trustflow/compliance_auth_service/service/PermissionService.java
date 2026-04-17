package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.dto.AccessPermissionsDto;

import java.util.UUID;

public interface PermissionService {
    AccessPermissionsDto getUserAccessPermissions(UUID userId);
    AccessPermissionsDto updateUserAccessPermissions(UUID userId, AccessPermissionsDto accessPermissionsDto);
}
