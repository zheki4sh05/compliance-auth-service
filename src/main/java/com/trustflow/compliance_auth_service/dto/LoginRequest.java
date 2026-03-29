package com.trustflow.compliance_auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Учётные данные для входа. Укажите email или username, не оба обязательны одновременно.")
public class LoginRequest {

    @Schema(description = "Email (удобно для UI)", example = "manager@company.com")
    private String email;

    @Schema(description = "Имя пользователя (альтернатива email)", example = "manager")
    private String username;

    @NotBlank(message = "Пароль обязателен")
    @Schema(
            description = "Пароль",
            example = "manager123",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String password;

    @Schema(
            description = "OAuth2 client id для выдачи токена (по умолчанию в сервисе — frontend-client)",
            example = "frontend-client"
    )
    private String clientId;
}
