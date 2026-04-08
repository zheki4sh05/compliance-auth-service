package com.trustflow.compliance_auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Запрос на регистрацию пользователя")
public class RegisterRequest {
    
    @NotBlank(message = "Email обязателен")
    @Schema(description = "Email пользователя", example = "user@example.com", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;
    
    @NotBlank(message = "Имя обязательно")
    @Schema(description = "Имя пользователя", example = "Иван", requiredMode = Schema.RequiredMode.REQUIRED)
    private String firstName;
    
    @NotBlank(message = "Фамилия обязательна")
    @Schema(description = "Фамилия пользователя", example = "Иванов", requiredMode = Schema.RequiredMode.REQUIRED)
    private String lastName;
    
    @NotBlank(message = "Пароль обязателен")
    @Schema(
            description = "Пароль пользователя (передаётся только в теле запроса, в ответе не возвращается)",
            example = "SecurePass123",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String password;
    
    @Schema(description = "Роль пользователя (если не указана, будет присвоена роль DEFAULT)", example = "DEFAULT")
    private String role;
    
    @Schema(description = "Идентификатор отдела")
    private String departmentId;

    @Schema(
            description = "OAuth2 client id для выдачи токенов после регистрации (как в /auth/login). Если не указан — используется frontend-client.",
            example = "frontend-client"
    )
    private String clientId;
}