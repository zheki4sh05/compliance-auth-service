package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.*;
import com.trustflow.compliance_auth_service.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/tokens")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    /**
     * Получить информацию о токене
     * GET /api/tokens/info
     */
    @GetMapping("/info")
    public ResponseEntity<TokenInfoDto> getTokenInfo(@RequestParam String token) {
        TokenInfoDto info = tokenService.getTokenInfo(token);
        return ResponseEntity.ok(info);
    }

    /**
     * Отозвать все токены пользователя (только для EXECUTIVE)
     * POST /api/tokens/revoke-all/{username}
     */
    @PreAuthorize("hasRole('EXECUTIVE')")
    @PostMapping("/revoke-all/{username}")
    public ResponseEntity<Void> revokeAllUserTokens(@PathVariable String username) {
        tokenService.revokeAllUserTokens(username);
        return ResponseEntity.ok().build();
    }
}

