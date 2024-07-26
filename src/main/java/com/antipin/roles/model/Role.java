package com.antipin.roles.model;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@Getter
public enum Role implements GrantedAuthority {

    USER,
    MODERATOR,
    ADMIN;

    @Override
    public String getAuthority() {
        return "ROLE_" + name();
    }
}
