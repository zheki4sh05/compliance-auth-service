package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.AbstractIntegrationTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustflow.compliance_auth_service.dto.AuthResponse;
import com.trustflow.compliance_auth_service.dto.LoginRequest;
import com.trustflow.compliance_auth_service.dto.TokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void loginShouldReturnTokens() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("manager@company.com");
        request.setPassword("manager123");
        request.setClientId("monitoring-service");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").exists())
                .andExpect(jsonPath("$.tokens").exists())
                .andExpect(jsonPath("$.tokens.accessToken").exists())
                .andExpect(jsonPath("$.tokens.refreshToken").exists());
    }

    @Test
    void validateTokenShouldReturnTrueForValidToken() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("manager@company.com");
        request.setPassword("manager123");
        request.setClientId("monitoring-service");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(response, AuthResponse.class);
        String accessToken = authResponse.getTokens().getAccessToken();

        mockMvc.perform(get("/api/auth/validate")
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }
}