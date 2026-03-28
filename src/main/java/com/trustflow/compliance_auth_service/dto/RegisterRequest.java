package com.trustflow.compliance_auth_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Запрос на регистрацию пользователя")
public class RegisterRequest {
    
    @NotBlank(message = "Email обязателен")
    @Schema(description = "Email пользователя", example = "user@example.com", required = true)
    private String email;
    
    @NotBlank(message = "Имя обязательно")
    @Schema(description = "Имя пользователя", example = "Иван", required = true)
    private String firstName;
    
    @NotBlank(message = "Фамилия обязательна")
    @Schema(description = "Фамилия пользователя", example = "Иванов", required = true)
    private String lastName;
    
    @NotBlank(message = "Пароль обязателен")
    @Schema(description = "Пароль пользователя", example = "password123", required = true)
    private String password;
    
    @Schema(description = "Роль пользователя (если не указана, будет присвоена роль DEFAULT)", example = "DEFAULT")
    private String role;
    
    @Schema(description = "Идентификатор отдела")
    private String departmentId;
}