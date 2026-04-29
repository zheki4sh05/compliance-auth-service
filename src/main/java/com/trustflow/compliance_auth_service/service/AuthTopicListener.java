package com.trustflow.compliance_auth_service.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustflow.compliance_auth_service.domain.User;
import com.trustflow.compliance_auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthTopicListener {

    private static final String ADD_USER_COMPANY_TYPE = "ADD_USER_COMPANY";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final UserRepository userRepository;

    @KafkaListener(
            topics = "${app.kafka.topics.auth}",
            groupId = "${spring.kafka.consumer.group-id}"
    )
    @Transactional
    public void listenAuthTopic(String payload) {
        JsonNode event;
        try {
            event = OBJECT_MAPPER.readTree(payload);
        } catch (IOException ex) {
            log.warn("Skipping malformed auth_topic message: {}", payload, ex);
            return;
        }

        String type = event.path("type").asText();
        if (!ADD_USER_COMPANY_TYPE.equals(type)) {
            return;
        }

        String userIdRaw = event.path("userId").asText(null);
        String companyIdRaw = event.path("companyId").asText(null);
        if (userIdRaw == null || companyIdRaw == null) {
            log.warn("Skipping ADD_USER_COMPANY message with missing fields: {}", payload);
            return;
        }

        UUID userId;
        UUID companyId;
        try {
            userId = UUID.fromString(userIdRaw);
            companyId = UUID.fromString(companyIdRaw);
        } catch (IllegalArgumentException ex) {
            log.warn("Skipping ADD_USER_COMPANY message with invalid UUIDs: {}", payload, ex);
            return;
        }

        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isEmpty()) {
            log.warn("User not found for ADD_USER_COMPANY event, userId={}", userId);
            return;
        }

        User user = userOptional.get();
        user.setCompanyId(companyId);
        userRepository.save(user);
        log.info("User company updated from auth_topic, userId={}, companyId={}", userId, companyId);
    }
}
