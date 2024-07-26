package com.antipin.roles.security;

import com.antipin.roles.exception.JwtExpiredException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expirationMs}")
    private int lifetime;

    public String generateToken(UserDetails userDetails) {
        SecretKey key = getSecretKey();
        Date issued = new Date();
        Date expiration = new Date(issued.getTime() + lifetime);
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities())
                .issuedAt(issued)
                .expiration(expiration)
                .signWith(key)
                .compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            return false;
        }
        String subject = claims.getSubject();
        if (!userDetails.getUsername().equals(subject)) {
            return false;
        }
        checkIfExpired(claims);
        return true;
    }

    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secret));
    }

    private void checkIfExpired(Claims claims) {
        if (claims.getExpiration().before(new Date())) {
            throw new JwtExpiredException();
        }
    }
}
