package com.trustflow.compliance_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.trustflow.compliance_auth_service.domain.enums.RoleType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Профиль пользователя")
public class UserProfileDto {

    @Schema(description = "ID пользователя", example = "3")
    private String id;

    @Schema(description = "Email", example = "ivan.ivanov@company.com")
    private String email;

    @Schema(description = "Имя", example = "Иван")
    private String firstName;

    @Schema(description = "Фамилия", example = "Иванов")
    private String lastName;

    @Schema(description = "Отчество", example = "Петрович")
    private String middleName;

    @Schema(description = "Роль пользователя", example = "MANAGER")
    private String role;

    @Schema(description = "Отдел", example = "Отдел закупок")
    private String department;

    @Schema(description = "Должность", example = "Менеджер по закупкам")
    private String position;

    @Schema(description = "Телефон", example = "+7 (999) 123-45-67")
    private String phone;

    @Schema(description = "URL аватара", example = "https://example.com/avatars/3.jpg")
    private String avatar;

    @Schema(description = "Права доступа")
    private List<String> permissions;

    @Schema(description = "Дата создания", example = "2023-01-15T10:00:00Z")
    private LocalDateTime createdAt;

    @Schema(description = "Последний вход", example = "2024-12-03T18:30:00Z")
    private LocalDateTime lastLoginAt;
}

