package com.trustflow.compliance_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CompanyEmployeeResponseDto {
    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private String role;
    private UUID companyId;
    private UUID departmentId;
    private String employeeId;
    private Boolean isFirstLogin;
}
