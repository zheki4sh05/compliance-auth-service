package com.trustflow.compliance_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Статус пользователя")
public class UserStatusDto {

    @JsonProperty("status")
    @Schema(description = "Статус пользователя: active или blocked", example = "active")
    private String status;
}
