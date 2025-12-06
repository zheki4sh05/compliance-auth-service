package com.trustflow.compliance_auth_service.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
public class TokenInfoDto {
    private String username;
    private Set<String> roles;
    private Set<String> scopes;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean active;
}

