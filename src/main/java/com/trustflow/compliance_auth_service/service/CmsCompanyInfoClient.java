package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.dto.CompanyEmployeeResponseDto;
import com.trustflow.compliance_auth_service.dto.EmployeeInternalInfoDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

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

    public String fetchCompanyIdByUserId(String userId, String authorizationHeader) {
        log.info("Calling cms-company-info: method=GET, url={}", "/company/id/" + userId);
        log.debug("cms-company-info request headers: Authorization={}", maskAuthorizationHeader(authorizationHeader));

        try {
            String responseBody = cmsCompanyInfoRestClient.get()
                    .uri("/company/id/{userId}", userId)
                    .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                    .retrieve()
                    .body(String.class);

            if (responseBody == null || responseBody.isBlank()) {
                log.info("fetchCompanyIdByUserId: complete userId={}, companyId=null (empty response)", userId);
                return null;
            }
            String companyId = normalizeCompanyId(responseBody);
            log.info("fetchCompanyIdByUserId: complete userId={}, companyId={}", userId, companyId);
            return companyId;
        } catch (Exception ex) {
            log.warn("Failed to fetch companyId from cms-company-info for user {}: {}", userId, ex.getMessage());
            return null;
        }
    }

    /**
     * Профиль сотрудника: cms-company-info {@code GET /employee/internal/id/{userId}}.
     */
    public EmployeeInternalInfoDto fetchEmployeeInternalByUserId(String userId, String authorizationHeader) {
        log.info(
                "Calling cms-company-info: method=GET, path=/employee/internal/id/, pathParamUserId={}, authorizationHeader={}",
                userId,
                maskAuthorizationHeader(authorizationHeader));

        try {
            EmployeeInternalInfoDto body = cmsCompanyInfoRestClient.get()
                    .uri("/employee/internal/id/{userId}", userId)
                    .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                    .retrieve()
                    .body(EmployeeInternalInfoDto.class);

            if (body == null) {
                log.info(
                        "cms-company-info GET /employee/internal/id/ completed with empty body, pathParamUserId={}",
                        userId);
                return null;
            }

            log.info(
                    "cms-company-info GET /employee/internal/id/ success. pathParamUserId={}, employeeId={}, departmentId={}, departmentName={}, departmentRole={}",
                    userId,
                    body.getEmployeeId(),
                    body.getDepartmentId(),
                    body.getDepartmentName(),
                    body.getDepartmentRole());

            return body;
        } catch (RestClientResponseException ex) {
            log.error(
                    "cms-company-info GET /employee/internal/id/ HTTP error. pathParamUserId={}, status={}, statusText={}, responseBody={}, authorizationHeader={}",
                    userId,
                    ex.getStatusCode().value(),
                    ex.getStatusText(),
                    ex.getResponseBodyAsString(StandardCharsets.UTF_8),
                    maskAuthorizationHeader(authorizationHeader),
                    ex);
            return null;
        } catch (Exception ex) {
            log.error(
                    "cms-company-info GET /employee/internal/id/ failed. pathParamUserId={}, authorizationHeader={}, causeType={}, errorMessage={}",
                    userId,
                    maskAuthorizationHeader(authorizationHeader),
                    ex.getClass().getName(),
                    ex.getMessage(),
                    ex);
            return null;
        }
    }

    /**
     * Список сотрудников компании из cms-company-info (источник правды по ролям для админки).
     */
    public List<CompanyEmployeeResponseDto> fetchCompanyEmployees(UUID companyId, String authorizationHeader) {
        log.info("Calling cms-company-info: method=GET, url=/companies/{}/employees", companyId);
        log.debug("cms-company-info request headers: Authorization={}", maskAuthorizationHeader(authorizationHeader));

        List<CompanyEmployeeResponseDto> body = cmsCompanyInfoRestClient.get()
                .uri("/companies/{companyId}/employees", companyId)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .retrieve()
                .body(new ParameterizedTypeReference<List<CompanyEmployeeResponseDto>>() {
                });

        if (body == null) {
            log.info("fetchCompanyEmployees: empty body, companyId={}", companyId);
            return List.of();
        }
        log.info("fetchCompanyEmployees: complete, companyId={}, count={}", companyId, body.size());
        return body;
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

    private String normalizeCompanyId(String raw) {
        String trimmed = raw.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            String companyId = extractJsonField(trimmed, "companyId");
            if (companyId != null && !companyId.isBlank()) {
                return companyId;
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
