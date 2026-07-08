package com.sunka.auth.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    public Mono<Boolean> validateCredentials(String email, String name) {
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/exists")
                        .queryParam("email", email.toLowerCase())
                        .build())
                .retrieve()
                .bodyToMono(Boolean.class)
                .doOnNext(result -> log.info("UserService exists check for {} returned {}", email, result))
                .onErrorResume(e -> {
                    log.error("Error calling UserService for {}: {}", email, e.getMessage());
                    return Mono.just(false);
                });
    }
}

