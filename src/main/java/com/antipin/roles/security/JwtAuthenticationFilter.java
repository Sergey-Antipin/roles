package com.antipin.roles.security;

import com.antipin.roles.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserService userService;

    private static final String HEADER_NAME = "Authorization";
    private static final String HEADER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractTokenFromRequest(request);

        if (token != null && validateToken(token)) {
            Authentication authentication = createAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("User {} has signed in", authentication.getPrincipal());
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader(HEADER_NAME);
        if (header == null || !header.startsWith(HEADER_PREFIX)) {
            return null;
        }
        return header.substring(HEADER_PREFIX.length());
    }

    private boolean validateToken(String token) {
        UserDetails userDetails = extractUserDetailsFromToken(token);
        return jwtUtil.validateToken(token, userDetails);
    }

    private Authentication createAuthentication(String token) {
        UserDetails userDetails = extractUserDetailsFromToken(token);
        return new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities());
    }

    private UserDetails extractUserDetailsFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(jwtUtil.getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        String username = claims.getSubject();
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("roles").toString().split(", "))
                .map(SimpleGrantedAuthority::new)
                .toList();
        return userService.loadUserByUsername(username);
    }
}

