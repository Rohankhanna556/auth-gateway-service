package com.sunka.auth.config;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
    private final String frontendBaseUrl;

    public GoogleOAuth2SuccessHandler(JwtUtil jwtUtil,
                                      AuthServiceClient authServiceClient,
                                      @Value("${frontend.base-url}") String frontendBaseUrl) {
        this.jwtUtil = jwtUtil;
        this.authServiceClient = authServiceClient;
        this.frontendBaseUrl = frontendBaseUrl;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
                                              Authentication authentication) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String email = oauthToken.getPrincipal().getAttribute("email");
        String name = oauthToken.getPrincipal().getAttribute("name");

        log.info("Google login success for {}", email);

        return authServiceClient.validateCredentials(email, name)
            .flatMap(userExists -> {
                ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
                if (userExists) {
                    return authServiceClient.findByEmail(email)
                        .flatMap(userdetails -> {
                            String username = userdetails.getOrDefault("username", "").toString();
                            String role = userdetails.getOrDefault("role", "USER").toString();
                            String token = jwtUtil.generateToken(username, email, role);

                            response.setStatusCode(HttpStatus.FOUND);
                            response.getHeaders().setLocation(
                                URI.create(frontendBaseUrl + "/home?token=" + token)
                            );
                            return response.setComplete();
                        });
                } else {
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(
                        URI.create(frontendBaseUrl + "/register?email=" + email)
                    );
                    return response.setComplete();
                }
            });
    }
}
