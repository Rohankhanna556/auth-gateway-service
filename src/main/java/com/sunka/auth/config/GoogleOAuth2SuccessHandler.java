package com.sunka.auth.config;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.sunka.auth.client.AuthServiceClient;

import reactor.core.publisher.Mono;

@Component
public class GoogleOAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(GoogleOAuth2SuccessHandler.class);

    private final JwtUtil jwtUtil;
    private final AuthServiceClient authServiceClient;

    public GoogleOAuth2SuccessHandler(JwtUtil jwtUtil, AuthServiceClient authServiceClient) {
        this.jwtUtil = jwtUtil;
        this.authServiceClient = authServiceClient;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
                                              Authentication authentication) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String email = oauthToken.getPrincipal().getAttribute("email");
        String name = oauthToken.getPrincipal().getAttribute("name");

        log.info("Google login success for email={}, name={}", email, name);

        return authServiceClient.validateCredentials(email, name)
            .doOnNext(userExists -> log.info("UserService returned userExists={} for {}", userExists, email))
            .flatMap(userExists -> {
                ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
                if (userExists) {
                    String token = jwtUtil.generateToken(email);
                    log.info("User exists, issuing JWT and redirecting to /home");
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(
                        URI.create("http://localhost:3000/home?token=" + token)
                    );
                } else {
                    log.warn("User not found, redirecting to /register");
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(
                        URI.create("http://localhost:3000/register?email=" + email)
                    );
                }
                return response.setComplete();
            });
    }
}
