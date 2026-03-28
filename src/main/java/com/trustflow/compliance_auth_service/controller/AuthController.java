package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.AuthResponse;
import com.trustflow.compliance_auth_service.dto.LoginRequest;
import com.trustflow.compliance_auth_service.dto.RegisterRequest;
import com.trustflow.compliance_auth_service.dto.RegisterResponse;
import com.trustflow.compliance_auth_service.dto.TokenResponse;
import com.trustflow.compliance_auth_service.service.TokenService;
import io.swagger.v3.oas.annotations.Operation;
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

    @Operation(summary = "Аутентификация пользователя")
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        AuthResponse authResponse = tokenService.login(request);
        return ResponseEntity.ok(authResponse);
    }

    @Operation(summary = "Регистрация пользователя")
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
