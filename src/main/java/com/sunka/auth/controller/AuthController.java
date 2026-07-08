package com.sunka.auth.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sunka.auth.client.AuthServiceClient;   // <-- import your Feign client interface
import com.sunka.auth.config.JwtUtil;
import com.sunka.auth.model.LoginRequest;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final AuthServiceClient authServiceClient;

    public AuthController(JwtUtil jwtUtil, AuthServiceClient authServiceClient) {
        this.jwtUtil = jwtUtil;
        this.authServiceClient = authServiceClient;
    }

    // Accept credentials in the request body
    @PostMapping("/login")
    public Mono<String> login(@RequestBody LoginRequest loginRequest) {
        return authServiceClient.validateCredentials(
                loginRequest.getUsername(),
                loginRequest.getPassword()
            )
            .map(valid -> {
                if (valid) {
                    return jwtUtil.generateToken(loginRequest.getUsername());
                } else {
                    return "Invalid credentials";
                }
            });
    }

}

