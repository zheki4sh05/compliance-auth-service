package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.*;
import com.trustflow.compliance_auth_service.service.*;
import io.swagger.v3.oas.annotations.*;
import io.swagger.v3.oas.annotations.media.*;
import io.swagger.v3.oas.annotations.responses.*;
import io.swagger.v3.oas.annotations.tags.*;
import lombok.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints для аутентификации и управления токенами")
public class AuthController {

    private final TokenService tokenService;

    @Operation(
            summary = "Аутентификация пользователя",
            description = "Получение Access и Refresh токенов по username и password"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Успешная аутентификация",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TokenResponse.class),
                            examples = @ExampleObject(
                                    value = "{\"access_token\":\"eyJhbGc...\",\"refresh_token\":\"eyJhbGc...\",\"token_type\":\"Bearer\",\"expires_in\":900,\"scope\":\"read write\"}"
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Неверные учетные данные"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Неверный client_id"
            )
    })
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Учетные данные пользователя",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = LoginRequest.class),
                            examples = @ExampleObject(
                                    value = "{\"username\":\"manager\",\"password\":\"manager123\",\"clientId\":\"monitoring-service\"}"
                            )
                    )
            )
            @RequestBody LoginRequest request
    ) {
        TokenResponse tokens = tokenService.authenticate(
                request.getUsername(),
                request.getPassword(),
                request.getClientId()
        );
        return ResponseEntity.ok(tokens);
    }

    @Operation(
            summary = "Обновление Access Token",
            description = "Получение нового Access Token с помощью Refresh Token"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Токен успешно обновлен",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TokenResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Недействительный Refresh Token"
            )
    })
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @Parameter(description = "Refresh Token", required = true, example = "eyJhbGciOiJSUzI1NiJ9...")
            @RequestParam String refreshToken,
            @Parameter(description = "Client ID", required = true, example = "monitoring-service")
            @RequestParam String clientId
    ) {
        TokenResponse tokens = tokenService.refreshAccessToken(refreshToken, clientId);
        return ResponseEntity.ok(tokens);
    }

    @Operation(
            summary = "Отзыв токена",
            description = "Отзыв Access или Refresh токена (logout)"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Токен успешно отозван"),
            @ApiResponse(responseCode = "400", description = "Недействительный токен")
    })
    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(
            @Parameter(description = "Access или Refresh Token для отзыва", required = true)
            @RequestParam String token
    ) {
        tokenService.revokeToken(token);
        return ResponseEntity.ok().build();
    }

    @Operation(
            summary = "Валидация токена",
            description = "Проверка действительности токена"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Результат валидации",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(type = "boolean"),
                            examples = @ExampleObject(value = "true")
                    )
            )
    })
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(
            @Parameter(description = "JWT токен для валидации", required = true)
            @RequestParam String token
    ) {
        boolean isValid = tokenService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }
}
