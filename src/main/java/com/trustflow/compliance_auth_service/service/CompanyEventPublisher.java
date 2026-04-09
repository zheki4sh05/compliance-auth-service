package com.trustflow.compliance_auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class CompanyEventPublisher {

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final NewTopic companyTopic;

    public void publishCompanyCreated(String companyName, UUID userId, String role) {
        String jsonPayload = "{\"event\":\"CREATED\",\"name\":\"" + escapeJson(companyName)
                + "\",\"userId\":\"" + userId
                + "\",\"role\":\"" + escapeJson(role) + "\"}";

        kafkaTemplate.send(companyTopic.name(), userId.toString(), jsonPayload)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish company event for userId={}", userId, ex);
                        return;
                    }
                    log.info("Company CREATED event published to topic={} for userId={}", companyTopic.name(), userId);
                });
    }

    private String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
