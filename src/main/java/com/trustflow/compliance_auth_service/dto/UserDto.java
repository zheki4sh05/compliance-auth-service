package com.trustflow.compliance_auth_service.dto;
import com.trustflow.compliance_auth_service.domain.enums.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private Set<RoleType> roles;
    private Boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String password;
}

