package com.trustflow.compliance_auth_service.service;



import com.trustflow.compliance_auth_service.dto.TokenInfoDto;
import com.trustflow.compliance_auth_service.dto.TokenResponse;

public interface TokenService {
    TokenResponse authenticate(String username, String password, String clientId);
    TokenResponse refreshAccessToken(String refreshToken, String clientId);
    void revokeToken(String token);
    boolean validateToken(String token);
    TokenInfoDto getTokenInfo(String token);
    void revokeAllUserTokens(String username);
}


