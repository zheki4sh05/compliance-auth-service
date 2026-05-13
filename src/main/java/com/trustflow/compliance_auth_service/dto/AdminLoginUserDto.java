package com.trustflow.compliance_auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminLoginUserDto {
    private String id;
    private String name;
    private String firstName;
    private String lastName;
    private String email;
    private String role;
    private String companyId;
    private String employeeId;
    private EmployeeInternalInfoDto employeeInternal;
    /** true, если у пользователя в {@code permissions.value} есть хотя бы одно право */
    private boolean hasAdminAccess;
}
