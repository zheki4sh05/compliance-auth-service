package com.trustflow.compliance_auth_service.dto;

import lombok.Data;

@Data
public class UserProfileUpdateRequestDto {
    private String email;
    private String firstName;
    private String lastName;
}
