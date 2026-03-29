package com.trustflow.compliance_auth_service.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .openapi("3.0.1")
                .info(new Info()
                        .title("Compliance Auth Service API")
                        .version("1.0.0")
                        .description("OAuth2 Authorization Server для системы управления рисками комплаенса. " +
                                "Предоставляет централизованную аутентификацию и авторизацию для микросервисов.")
                        .contact(new Contact()
                                .name("TrustFlow Team")
                                .email("support@trustflow.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.html")))
                .addServersItem(new Server()
                        .url("http://localhost:9091")
                        .description("Local Development Server"))
                .addServersItem(new Server()
                        .url("http://auth-service:9091")
                        .description("Docker Environment"))
                .components(new Components()
                        .addSecuritySchemes("oauth2", new SecurityScheme()
                                .type(SecurityScheme.Type.OAUTH2)
                                .description("OAuth2 Authorization Code flow (PKCE) for Swagger UI")
                                .flows(new OAuthFlows()
                                        .authorizationCode(new OAuthFlow()
                                                .authorizationUrl("http://localhost:9091/oauth2/authorize")
                                                .tokenUrl("http://localhost:9091/oauth2/token")
                                                .scopes(new io.swagger.v3.oas.models.security.Scopes()
                                                        .addString("read", "Read access")
                                                        .addString("write", "Write access"))))))
                .addSecurityItem(new SecurityRequirement().addList("oauth2", java.util.List.of("read", "write")));
    }
}
