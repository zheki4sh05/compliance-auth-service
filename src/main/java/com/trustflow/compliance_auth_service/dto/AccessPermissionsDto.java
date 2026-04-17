package com.trustflow.compliance_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Набор permissions пользователя")
public class AccessPermissionsDto {

    @JsonProperty("accessPermissions")
    @Schema(description = "Permissions пользователя", example = "[\"view_users_page\", \"edit_users\"]")
    private List<String> accessPermissions;
}
