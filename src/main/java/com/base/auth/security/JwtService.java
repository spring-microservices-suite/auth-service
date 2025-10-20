package com.base.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Value("${app.access.token.expiration-minutes:15}")
    private long expirationMinutes;

    @Value("${app.refresh.token.expiration-minutes:120}")
    private long refreshExpirationMinutes;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generate access token with userId as subject and role as claim
     */
    public String generateAccessToken(String userId, String role) {
        return Jwts.builder()
                .setSubject(userId) // subject is always userId
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMinutes * 60 * 1000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Generate refresh token with userId as subject
     */
    public String generateRefreshToken(String userId) {
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpirationMinutes * 60 * 1000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // consistent signing
                .compact();
    }

    /**
     * Validate token signature and expiration
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(getSigningKey()).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract userId from token
     */
    public String extractUserId(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extract role from token
     */
    public String extractRole(String token) {
        return (String) extractAllClaims(token).get("role");
    }

    /**
     * Check if token is valid for a given userId
     */
    public boolean isTokenValid(String token, String userId) {
        return userId.equals(extractUserId(token)) && !isExpired(token);
    }

    /**
     * Extract expiration
     */
    public Instant extractExpiration(String token) {
        return extractAllClaims(token).getExpiration().toInstant();
    }

    /**
     * Check if token is expired
     */
    private boolean isExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    /**
     * Extract all claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }
}
