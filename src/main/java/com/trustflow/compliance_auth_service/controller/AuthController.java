package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.AuthResponse;
import com.trustflow.compliance_auth_service.dto.LoginRequest;
import com.trustflow.compliance_auth_service.dto.RegisterRequest;
import com.trustflow.compliance_auth_service.dto.TokenResponse;
import com.trustflow.compliance_auth_service.service.TokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthController {

    private final TokenService tokenService;

    @Operation(
            summary = "Аутентификация пользователя",
            description = """
                    Публичный endpoint: Bearer не нужен. Тестовые пользователи из миграции V1:
                    manager@company.com / manager123,
                    supervisor@company.com / supervisor123,
                    executive@company.com / executive123.
                    После успешного ответа скопируйте accessToken в Authorize → Bearer Authentication для вызовов /api/**.
                    """,
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginRequest.class),
                            examples = {
                                    @ExampleObject(
                                            name = "По email (manager)",
                                            summary = "MANAGER",
                                            value = """
                                                    {
                                                      "email": "manager@company.com",
                                                      "password": "manager123",
                                                      "clientId": "frontend-client"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "По email (executive)",
                                            summary = "EXECUTIVE",
                                            value = """
                                                    {
                                                      "email": "executive@company.com",
                                                      "password": "executive123",
                                                      "clientId": "frontend-client"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "По username",
                                            summary = "supervisor",
                                            value = """
                                                    {
                                                      "username": "supervisor",
                                                      "password": "supervisor123",
                                                      "clientId": "frontend-client"
                                                    }
                                                    """
                                    )
                            }
                    )
            )
    )
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse authResponse = tokenService.login(request);
        return ResponseEntity.ok(authResponse);
    }

    @Operation(
            summary = "Регистрация пользователя",
            description = """
                    Публичный endpoint. После создания пользователя возвращаются токены для указанного OAuth2 client_id.
                    Укажите clientId в теле (как у /auth/login), например frontend-client, swagger-ui-client или monitoring-service.
                    Если clientId не передан — используется frontend-client.
                    """,
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = RegisterRequest.class),
                            examples = @ExampleObject(
                                    name = "С clientId",
                                    value = """
                                            {
                                              "email": "new.user@company.com",
                                              "firstName": "Иван",
                                              "lastName": "Иванов",
                                              "password": "SecurePass123",
                                              "departmentId": "dept-1",
                                              "clientId": "frontend-client"
                                            }
                                            """
                            )
                    )
            )
    )
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = tokenService.register(request);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Обновление Access Token")
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestParam String refreshToken,
            @RequestParam String clientId
    ) {
        TokenResponse tokens = tokenService.refreshAccessToken(refreshToken, clientId);
        return ResponseEntity.ok(tokens);
    }

    @Operation(summary = "Отзыв токена")
    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(@RequestParam String token) {
        tokenService.revokeToken(token);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Валидация токена")
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestParam String token) {
        boolean isValid = tokenService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }
}
