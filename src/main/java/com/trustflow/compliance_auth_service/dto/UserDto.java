package com.trustflow.compliance_auth_service.dto;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.trustflow.compliance_auth_service.domain.enums.*;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Data
public class UserDto {
    private UUID id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Set<RoleType> roles;
    private Boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @Schema(accessMode = Schema.AccessMode.WRITE_ONLY, description = "Пароль используется только во входящих запросах")
    private String password;
}

