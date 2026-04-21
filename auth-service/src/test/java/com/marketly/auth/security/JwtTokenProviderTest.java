package com.marketly.auth.security;

import com.marketly.auth.config.JwtProperties;
import com.marketly.auth.domain.Role;
import com.marketly.auth.domain.User;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenProviderTest {

    @Test
    void shouldGenerateAndParseToken() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("marketly-marketly-marketly-marketly-secret-123456");
        properties.setExpirationMs(86_400_000L);

        JwtTokenProvider provider = new JwtTokenProvider(properties);

        User user = new User();
        user.setId(UUID.fromString("11111111-1111-1111-1111-111111111111"));
        user.setEmail("seller@marketly.com");
        user.setPassword("hashed-password");
        user.setRole(Role.ROLE_SELLER);

        String token = provider.generateToken(user);

        assertTrue(provider.validateToken(token));
        assertEquals("seller@marketly.com", provider.extractEmail(token));
        assertEquals(user.getId(), provider.extractUserId(token));
    }
}
