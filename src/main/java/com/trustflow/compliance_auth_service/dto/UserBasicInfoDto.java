package com.trustflow.compliance_auth_service.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserBasicInfoDto {
    private String firstName;
    private String lastName;
    private String username;
}
