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
}
