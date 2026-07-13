package com.sunka.auth.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sunka.auth.client.AuthServiceClient;
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

    @PostMapping("/login")
    public Mono<String> login(@RequestBody LoginRequest loginRequest) {
        return authServiceClient.validateCredentials(
                loginRequest.getUsername(),
                loginRequest.getPassword()
            )
            .flatMap(valid -> {
                if (valid) {
                    // Fetch user details reactively
                    return authServiceClient.findByUsername(loginRequest.getUsername())
                        .map(userDetails -> {
                            String username = userDetails.get("username").toString();
                            String email = userDetails.get("email").toString();
                            String role = userDetails.get("role").toString();
                            return jwtUtil.generateToken(username, email, role);
                        });
                } else {
                    return Mono.just("Invalid credentials");
                }
            });
    }
    
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", jwt.getClaim("sub"));   // or "username" claim if you set it
        profile.put("email", jwt.getClaim("email"));
        profile.put("role", jwt.getClaim("role"));

        return ResponseEntity.ok(profile);
    }
}
