package com.marketly.auth.dto;

import java.util.UUID;

public record AuthResponse(
        String token,
        String tokenType,
        long expiresInMs,
        UUID userId,
        String email,
        String role
) {
}
