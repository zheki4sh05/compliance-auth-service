package com.trustflow.compliance_auth_service.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Configuration
@Slf4j
public class AuthorizationServerConfig {

    @Value("${oauth2.authorization-server.issuer-url}")
    private String issuerUrl;

    @Value("${oauth2.authorization-server.token.access-token.time-to-live}")
    private long accessTokenTTL;

    @Value("${oauth2.authorization-server.token.refresh-token.time-to-live}")
    private long refreshTokenTTL;

    @Value("${oauth2.authorization-server.token.refresh-token.reuse}")
    private boolean reuseRefreshToken;

    @Value("${oauth2.authorization-server.jwt.private-key-pem}")
    private String privateKeyPem;

    @Value("${oauth2.authorization-server.jwt.public-key-pem:}")
    private String publicKeyPem;

    @Value("${oauth2.authorization-server.jwt.key-id:auth-service-rsa-key}")
    private String keyId;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/**", "/api/users/**", "/api/tokens/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")
                        )
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                );

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository repository =
                new JdbcRegisteredClientRepository(jdbcTemplate);

        // Регистрация всех клиентов
        registerClientIfNotExists(repository, "swagger-ui-client", createSwaggerUiClient());
        registerClientIfNotExists(repository, "frontend-client", createFrontendClient());
        registerClientIfNotExists(repository, "monitoring-service", createMonitoringServiceClient());
        registerClientIfNotExists(repository, "rules-service", createRulesServiceClient());
        registerClientIfNotExists(repository, "workflow-service", createWorkflowServiceClient());
        registerClientIfNotExists(repository, "notification-service", createNotificationServiceClient());

        return repository;
    }

    /**
     * Регистрирует клиента только если он не существует
     */
    private void registerClientIfNotExists(
            JdbcRegisteredClientRepository repository,
            String clientId,
            RegisteredClient client) {

        try {
            RegisteredClient existingClient = repository.findByClientId(clientId);
            if (existingClient == null) {
                repository.save(client);
                log.info("Registered OAuth2 client: {}", clientId);
            } else {
                log.info("OAuth2 client already exists: {}", clientId);
            }
        } catch (Exception e) {
            log.warn("Could not register client {}: {}", clientId, e.getMessage());
        }
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {

        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        if (jwtCustomizer != null) {
            jwtGenerator.setJwtCustomizer(jwtCustomizer);
        }

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator
        );
    }


    private RegisteredClient createMonitoringServiceClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("monitoring-service")
                .clientSecret("{bcrypt}$2a$12$LQv3c1yqBWVHxkltdWFQg.WJw1oXNAYYzGqnXxzzfQZgI4g6KdOYi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8081/login/oauth2/code/auth-server")
                .scope("read")
                .scope("write")
                .tokenSettings(createTokenSettings())
                .clientSettings(createClientSettings())
                .build();
    }

    private RegisteredClient createRulesServiceClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("rules-service")
                .clientSecret("{bcrypt}$2a$12$LQv3c1yqBWVHxkltdWFQg.WJw1oXNAYYzGqnXxzzfQZgI4g6KdOYi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8082/login/oauth2/code/auth-server")
                .scope("read")
                .scope("write")
                .scope("rules:manage")
                .tokenSettings(createTokenSettings())
                .clientSettings(createClientSettings())
                .build();
    }

    private RegisteredClient createWorkflowServiceClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("workflow-service")
                .clientSecret("{bcrypt}$2a$12$LQv3c1yqBWVHxkltdWFQg.WJw1oXNAYYzGqnXxzzfQZgI4g6KdOYi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8083/login/oauth2/code/auth-server")
                .scope("read")
                .scope("write")
                .scope("workflow:execute")
                .tokenSettings(createTokenSettings())
                .clientSettings(createClientSettings())
                .build();
    }

    private RegisteredClient createNotificationServiceClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("notification-service")
                .clientSecret("{bcrypt}$2a$12$LQv3c1yqBWVHxkltdWFQg.WJw1oXNAYYzGqnXxzzfQZgI4g6KdOYi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8084/login/oauth2/code/auth-server")
                .scope("read")
                .scope("notifications:send")
                .tokenSettings(createTokenSettings())
                .clientSettings(createClientSettings())
                .build();
    }

    private RegisteredClient createFrontendClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("frontend-client")
                .clientSecret("{bcrypt}$2a$12$LQv3c1yqBWVHxkltdWFQg.WJw1oXNAYYzGqnXxzzfQZgI4g6KdOYi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client для SPA
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .scope("read")
                .scope("write")
                .tokenSettings(createTokenSettings())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true) // PKCE для SPA
                        .build())
                .build();
    }

    private RegisteredClient createSwaggerUiClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("swagger-ui-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:9091/swagger-ui/oauth2-redirect.html")
                .scope("read")
                .scope("write")
                .tokenSettings(createTokenSettings())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .build();
    }

    private TokenSettings createTokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(accessTokenTTL))
                .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTTL))
                .reuseRefreshTokens(reuseRefreshToken) // Refresh token rotation
                .build();
    }

    private ClientSettings createClientSettings() {
        return ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(true) // PKCE для дополнительной безопасности
                .build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(
                jdbcTemplate,
                registeredClientRepository
        );
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAPrivateKey privateKey = parsePrivateKey(privateKeyPem);
        RSAPublicKey publicKey = parseOrDerivePublicKey(publicKeyPem, privateKey);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private RSAPrivateKey parsePrivateKey(String pem) {
        try {
            if (pem == null || pem.isBlank()) {
                throw new IllegalStateException("Missing private RSA key. Set oauth2.authorization-server.jwt.private-key-pem");
            }
            String normalizedPem = normalizePem(pem);
            String clean = normalizedPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(clean);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to parse RSA private key from environment", ex);
        }
    }

    private RSAPublicKey parseOrDerivePublicKey(String pem, RSAPrivateKey privateKey) {
        if (pem != null && !pem.isBlank()) {
            try {
                String normalizedPem = normalizePem(pem);
                String clean = normalizedPem
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "");
                byte[] keyBytes = Base64.getDecoder().decode(clean);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
            } catch (Exception ex) {
                throw new IllegalStateException("Failed to parse RSA public key from environment", ex);
            }
        }

        try {
            if (privateKey instanceof RSAPrivateCrtKey rsaPrivateCrtKey) {
                BigInteger modulus = rsaPrivateCrtKey.getModulus();
                BigInteger publicExponent = rsaPrivateCrtKey.getPublicExponent();
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
                return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to derive RSA public key from private key", ex);
        }

        throw new IllegalStateException("Public key is missing and cannot be derived from private key format");
    }

    private String normalizePem(String pem) {
        return pem.replace("\\n", "\n").trim();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUrl)
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            JwtEncodingContext jwtContext = (JwtEncodingContext) context;

            // Добавляем кастомные claims в токен
            if (jwtContext.getPrincipal() != null) {
                jwtContext.getClaims().claim("user_name", jwtContext.getPrincipal().getName());
            }

            // Добавляем client id в claims
            if (jwtContext.getRegisteredClient() != null) {
                jwtContext.getClaims().claim("client_id", jwtContext.getRegisteredClient().getId());
            }

            log.debug("Customizing JWT token for: {}", jwtContext.getPrincipal() != null ?
                    jwtContext.getPrincipal().getName() : "unknown");
        };
    }
}
