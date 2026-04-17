package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.AccessPermissionsDto;
import com.trustflow.compliance_auth_service.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "Permission Management", description = "Endpoints для управления permissions пользователей")
@SecurityRequirement(name = "Bearer Authentication")
public class PermissionController {

    private final PermissionService permissionService;

    @Operation(summary = "Получить permissions пользователя")
    @GetMapping("/{id}/access")
    public ResponseEntity<AccessPermissionsDto> getUserAccessPermissions(@PathVariable UUID id) {
        return ResponseEntity.ok(permissionService.getUserAccessPermissions(id));
    }

    @Operation(summary = "Обновить permissions пользователя")
    @PutMapping("/{id}/access")
    public ResponseEntity<AccessPermissionsDto> updateUserAccessPermissions(
            @PathVariable UUID id,
            @RequestBody AccessPermissionsDto accessPermissionsDto) {
        return ResponseEntity.ok(permissionService.updateUserAccessPermissions(id, accessPermissionsDto));
    }
}
