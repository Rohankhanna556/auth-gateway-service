package com.sunka.auth.config;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import io.jsonwebtoken.security.Keys;

@Configuration
public class SecurityConfig {

    @Value("${jwt.secret}") 
    String secret;

    private final GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;

    public SecurityConfig(GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler) {
        this.googleOAuth2SuccessHandler = googleOAuth2SuccessHandler;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers(
                    // Swagger + OpenAPI docs
                    "/swagger-ui.html",
                    "/swagger-ui/**",
                    "/v3/api-docs/**",
                    "/api-docs/**",

                    // User service register endpoint
                    "/user/api/users/register",

                    // Auth service login endpoint
                    "/api/auth/login",

                    // Google OAuth2 login flow
                    "/oauth2/**"
                ).permitAll()
                .anyExchange().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2.authenticationSuccessHandler(googleOAuth2SuccessHandler))
            .build();
    }

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(@Value("${jwt.secret}") String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return NimbusReactiveJwtDecoder.withSecretKey(key).build();
    }
}
