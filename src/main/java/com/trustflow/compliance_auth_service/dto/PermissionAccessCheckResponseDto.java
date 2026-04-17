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
@Schema(description = "Результат проверки наличия permission у пользователя")
public class PermissionAccessCheckResponseDto {

    @JsonProperty("access")
    @Schema(description = "Статус доступа", example = "permit", allowableValues = {"permit", "denied"})
    private String access;
}
