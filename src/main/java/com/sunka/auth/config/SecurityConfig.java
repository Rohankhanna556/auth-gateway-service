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

import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${app.cors.allowed-origins:http://localhost:3000}")
    private String[] allowedOrigins;  // safer than List<String> with @Value

    private final GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;

    public SecurityConfig(GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler) {
        this.googleOAuth2SuccessHandler = googleOAuth2SuccessHandler;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                            ReactiveJwtDecoder jwtDecoder) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(cors -> cors.configurationSource(exchange -> {
                org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
                config.setAllowCredentials(true);
                config.setAllowedOrigins(Arrays.asList(allowedOrigins));
                config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
                config.setAllowedHeaders(List.of("*"));
                return config;
            }))
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers(
                    "/swagger-ui.html", "/swagger-ui/**",
                    "/v3/api-docs/**", "/api-docs/**",
                    "/user/api/users/register",
                    "/api/auth/login",
                    "/book/api/books/**",
                    "/book/api/chapters/**",
                    "/book/api/pages/**",
                    "/oauth2/**"
                ).permitAll()
                .anyExchange().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2.authenticationSuccessHandler(googleOAuth2SuccessHandler))
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
            .build();
    }

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return NimbusReactiveJwtDecoder.withSecretKey(key).build();
    }
}
