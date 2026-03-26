package com.trustflow.compliance_auth_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserResponse {
    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private String role;
    private String departmentId;
    private Boolean isFirstLogin;
}