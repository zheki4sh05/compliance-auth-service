package com.trustflow.compliance_auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
@Slf4j
@RequiredArgsConstructor
public class CmsCompanyInfoClient {

    private final @Qualifier("cmsCompanyInfoRestClient") RestClient cmsCompanyInfoRestClient;

    public String fetchEmployeeId(String accessToken) {
        String maskedToken = maskToken(accessToken);
        String tokenUserId = extractUserIdFromJwt(accessToken);
        log.info("Calling cms-company-info: method=GET, url={}", "/employee/id");
        log.debug("cms-company-info request headers: Authorization=Bearer {}", maskedToken);
        log.debug("cms-company-info token diagnostics: userIdFromJwt={}", tokenUserId);

        try {
            String responseBody = cmsCompanyInfoRestClient.get()
                    .uri("/employee/id")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .header("X-User-Id", tokenUserId != null ? tokenUserId : "")
                    .retrieve()
                    .body(String.class);

            if (responseBody == null || responseBody.isBlank()) {
                return null;
            }
            return normalizeEmployeeId(responseBody);
        } catch (Exception ex) {
            log.warn("Failed to fetch employeeId from cms-company-info: {}", ex.getMessage());
            return null;
        }
    }

    public String fetchEmployeeByUserId(String userId, String authorizationHeader) {
        log.info("Calling cms-company-info: method=GET, url={}", "/employee/" + userId);
        log.debug("cms-company-info request headers: Authorization={}", maskAuthorizationHeader(authorizationHeader));

        return cmsCompanyInfoRestClient.get()
                .uri("/employee/{userId}", userId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .retrieve()
                .body(String.class);
    }

    private String maskToken(String token) {
        if (token == null || token.isBlank()) {
            return "<empty>";
        }
        if (token.length() <= 12) {
            return "***";
        }
        return token.substring(0, 8) + "..." + token.substring(token.length() - 4);
    }

    private String maskAuthorizationHeader(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return "<empty>";
        }
        if (!authorizationHeader.startsWith("Bearer ")) {
            return "***";
        }
        return "Bearer " + maskToken(authorizationHeader.substring("Bearer ".length()));
    }

    private String extractUserIdFromJwt(String token) {
        try {
            if (token == null || token.isBlank() || !token.contains(".")) {
                return null;
            }
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String userId = extractJsonField(payloadJson, "userId");
            if (userId != null && !userId.isBlank()) {
                return userId;
            }
            return extractJsonField(payloadJson, "user_id");
        } catch (Exception ex) {
            log.warn("Failed to inspect JWT payload for userId: {}", ex.getMessage());
            return null;
        }
    }

    private String normalizeEmployeeId(String raw) {
        String trimmed = raw.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            String employeeId = extractJsonField(trimmed, "employeeId");
            if (employeeId != null && !employeeId.isBlank()) {
                return employeeId;
            }
            String id = extractJsonField(trimmed, "id");
            if (id != null && !id.isBlank()) {
                return id;
            }
        }
        return trimmed.replace("\"", "");
    }

    private String extractJsonField(String json, String fieldName) {
        String token = "\"" + fieldName + "\"";
        int fieldPos = json.indexOf(token);
        if (fieldPos < 0) {
            return null;
        }
        int colonPos = json.indexOf(':', fieldPos + token.length());
        if (colonPos < 0) {
            return null;
        }
        int valueStart = colonPos + 1;
        while (valueStart < json.length() && Character.isWhitespace(json.charAt(valueStart))) {
            valueStart++;
        }
        if (valueStart >= json.length()) {
            return null;
        }
        if (json.charAt(valueStart) == '"') {
            int valueEnd = json.indexOf('"', valueStart + 1);
            if (valueEnd > valueStart) {
                return json.substring(valueStart + 1, valueEnd);
            }
            return null;
        }
        int commaPos = json.indexOf(',', valueStart);
        int endBracePos = json.indexOf('}', valueStart);
        int valueEnd = commaPos >= 0 && commaPos < endBracePos ? commaPos : endBracePos;
        if (valueEnd < 0) {
            return null;
        }
        return json.substring(valueStart, valueEnd).trim();
    }
}
