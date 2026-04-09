package com.trustflow.compliance_auth_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean("cmsCompanyInfoRestClient")
    public RestClient cmsCompanyInfoRestClient(
            @Value("${integration.cms-company-info.base-url:http://localhost:9092}") String baseUrl) {
        return RestClient.builder()
                .baseUrl(baseUrl)
                .build();
    }
}
