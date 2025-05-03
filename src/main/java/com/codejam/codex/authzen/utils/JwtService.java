package com.codejam.codex.authzen.utils;

import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token.expiry-ms}")
    private long accessTokenExpiry;

    @Value("${jwt.refresh-token.expiry-ms}")
    private long refreshTokenExpiry;

    private final Map<String, String> blacklistedTokens = new ConcurrentHashMap<>();

    @PostConstruct
    public void validateSecretLength() {
        if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
            throw new IllegalStateException("JWT secret key must not be null or empty");
        }
        if (jwtSecret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("JWT secret key must be at least 32 bytes (256 bits) long");
        }
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    public Date extractExpiration(String token) {
        try {
            return extractClaim(token, Claims::getExpiration);
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }

    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> resolver) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserResponse userDetails) {
        if (token == null || userDetails == null) {
            return false;
        }
        try {
            if (isTokenBlacklisted(token)) {
                return false;
            }
            final String username = extractUsername(token);
            return username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isTokenValid(String token) {
        if (token == null) {
            return false;
        }
        try {
            if (isTokenBlacklisted(token)) {
                return false;
            }
            Claims claims = extractAllClaims(token);
            return claims != null && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String generateAccessToken(UserResponse userResponse) {
        if (userResponse == null) {
            throw new IllegalArgumentException("User response cannot be null");
        }
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userResponse.getId());
        claims.put("username", userResponse.getUsername());
        claims.put("roles", userResponse.getRoles());
        claims.put("permissions", userResponse.getPermissions());
        claims.put("type", "access");
        return buildToken(claims, userResponse.getUsername(), accessTokenExpiry);
    }

    public String generateRefreshToken(UserResponse userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User details cannot be null");
        }
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userDetails.getId());
        claims.put("username", userDetails.getUsername());
        claims.put("type", "refresh");
        return buildToken(claims, userDetails.getUsername(), refreshTokenExpiry);
    }

    private String buildToken(Map<String, Object> claims, String subject, long expiry) {
        if (subject == null || subject.trim().isEmpty()) {
            throw new IllegalArgumentException("Subject cannot be null or empty");
        }
        if (expiry <= 0) {
            throw new IllegalArgumentException("Expiry must be positive");
        }
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiry))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    boolean isTokenExpired(String token) {
        try {
            Date expiration = extractExpiration(token);
            return expiration == null || expiration.before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return true;
        }
    }

    private Claims extractAllClaims(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .setAllowedClockSkewSeconds(2)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public List<String> extractPermissions(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Object permissionsObj = claims.get("permissions");
            if (permissionsObj instanceof List) {
                return (List<String>) permissionsObj;
            }
            return new ArrayList<>();
        } catch (JwtException | IllegalArgumentException e) {
            return new ArrayList<>();
        }
    }

    public boolean isTokenBlacklisted(String token) {
        return token != null && blacklistedTokens.containsKey(token);
    }

    public void blacklistToken(String token) {
        if (token != null && !token.trim().isEmpty()) {
            blacklistedTokens.put(token, new Date().toString());
        }
    }

    public void removeExpiredBlacklistedTokens() {
        Date now = new Date();
        blacklistedTokens.entrySet().removeIf(entry -> {
            try {
                Date expiration = extractExpiration(entry.getKey());
                return expiration != null && expiration.before(now);
            } catch (JwtException | IllegalArgumentException e) {
                return true;
            }
        });
    }
}