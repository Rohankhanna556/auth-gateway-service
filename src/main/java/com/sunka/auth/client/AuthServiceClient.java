package com.sunka.auth.client;

import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Component
public class AuthServiceClient {
    private static final Logger log = LoggerFactory.getLogger(AuthServiceClient.class);

    private final WebClient webClient;

    public AuthServiceClient(WebClient.Builder builder) {
        this.webClient = builder.baseUrl("http://localhost:8081/api/users").build();
    }

    public Mono<Boolean> validateCredentials(String username, String name) {
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/exists")
                        .queryParam("username", username.toLowerCase())
                        .build())
                .retrieve()
                .bodyToMono(Boolean.class)
                .doOnNext(result -> log.info("UserService exists check for {} returned {}", username, result))
                .onErrorResume(e -> {
                    log.error("Error calling UserService for {}: {}", username, e.getMessage());
                    return Mono.just(false);
                });
    }
    
    public Mono<Map<String, Object>> findByEmail(String email) {
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/find-by-email")
                        .queryParam("email", email.toLowerCase())
                        .build())
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .doOnNext(user -> log.info("UserService returned user={} for {}", user, email))
                .onErrorResume(e -> {
                    log.error("Error calling UserService for {}: {}", email, e.getMessage());
                    return Mono.just(Collections.emptyMap());
                });
    }
    
    public Mono<Map<String, Object>> findByUsername(String username) {
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/find-by-username")
                        .queryParam("username", username.toLowerCase())
                        .build())
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .doOnNext(user -> log.info("UserService returned user={} for {}", user, username))
                .onErrorResume(e -> {
                    log.error("Error calling UserService for {}: {}", username, e.getMessage());
                    return Mono.just(Collections.emptyMap());
                });
    }
}

