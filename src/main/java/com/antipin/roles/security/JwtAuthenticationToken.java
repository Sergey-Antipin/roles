package com.antipin.roles.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.security.auth.Subject;
import java.util.Collection;

public class JwtAuthenticationToken implements Authentication {

    private UserDetails userDetails;

    private String token;

    private Collection<? extends GrantedAuthority> authorities;

    private boolean authenticated;

    public JwtAuthenticationToken(UserDetails userDetails, String token, Collection<? extends GrantedAuthority> authorities) {
        this.userDetails = userDetails;
        this.token = token;
        this.authorities = authorities;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return userDetails;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return userDetails.getUsername();
    }

    @Override
    public boolean implies(Subject subject) {
        return Authentication.super.implies(subject);
    }
}
