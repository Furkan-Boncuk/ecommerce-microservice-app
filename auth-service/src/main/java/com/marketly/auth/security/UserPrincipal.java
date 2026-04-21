package com.marketly.auth.security;

import com.marketly.auth.domain.User;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class UserPrincipal implements UserDetails {

    private final UUID userId;
    private final String email;
    private final String password;
    private final boolean enabled;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserPrincipal(UUID userId, String email, String password, boolean enabled, Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.email = email;
        this.password = password;
        this.enabled = enabled;
        this.authorities = authorities;
    }

    public static UserPrincipal fromUser(User user) {
        return new UserPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                user.isEnabled(),
                List.<GrantedAuthority>of(new SimpleGrantedAuthority(user.getRole().name()))
        );
    }

    public static UserPrincipal fromClaims(Claims claims) {
        Object rolesValue = claims.get("roles");
        Collection<GrantedAuthority> authorities = Collections.emptyList();
        if (rolesValue instanceof List<?> rawRoles) {
            authorities = rawRoles.stream()
                    .map(String::valueOf)
                    .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role))
                    .toList();
        }
        return new UserPrincipal(
                UUID.fromString(String.valueOf(claims.get("userId"))),
                claims.getSubject(),
                "",
                true,
                authorities
        );
    }

    public UUID getUserId() {
        return userId;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}


