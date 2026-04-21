package com.marketly.auth.controller;

import com.marketly.auth.dto.AuthResponse;
import com.marketly.auth.dto.LoginRequest;
import com.marketly.auth.dto.RegisterRequest;
import com.marketly.auth.security.UserPrincipal;
import com.marketly.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(@AuthenticationPrincipal UserPrincipal principal) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("userId", principal.getUserId().toString());
        response.put("email", principal.getUsername());
        response.put("roles", principal.getAuthorities().stream().map(Object::toString).toList());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/seller/ping")
    @PreAuthorize("hasRole('SELLER')")
    public ResponseEntity<Map<String, String>> sellerPing() {
        return ResponseEntity.ok(Map.of("message", "seller-ok"));
    }
}
