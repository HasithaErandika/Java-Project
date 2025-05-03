package com.codejam.codex.authzen.utils;

import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    private static final String TOKEN_TYPE_CLAIM = "token_type";
    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String REFRESH_TOKEN_TYPE = "refresh";
    private static final long TOKEN_REVOCATION_WINDOW = TimeUnit.HOURS.toMillis(24);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token.expiry-ms}")
    private long accessTokenExpiry;

    @Value("${jwt.refresh-token.expiry-ms}")
    private long refreshTokenExpiry;

    private final Map<String, TokenRevocationInfo> revokedTokens = new ConcurrentHashMap<>();

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
        if (token == null || token.trim().isEmpty()) {
            return true;
        }

        TokenRevocationInfo info = revokedTokens.get(token);
        if (info != null) {
            if (info.isExpired()) {
                revokedTokens.remove(token);
                return false;
            }
            return true;
        }
        return false;
    }

    public void blacklistToken(String token, String reason) {
        if (token != null && !token.trim().isEmpty()) {
            revokedTokens.put(token, new TokenRevocationInfo(reason));
            logger.info("Token blacklisted: {}", reason);
        }
    }

    public void cleanupExpiredBlacklistedTokens() {
        revokedTokens.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    public boolean isRefreshToken(String token) {
        Claims claims = extractAllClaims(token);
        if (claims == null) {
            return false;
        }
        String tokenType = claims.get(TOKEN_TYPE_CLAIM, String.class);
        return REFRESH_TOKEN_TYPE.equals(tokenType);
    }

    public boolean isAccessToken(String token) {
        Claims claims = extractAllClaims(token);
        if (claims == null) {
            return false;
        }
        String tokenType = claims.get(TOKEN_TYPE_CLAIM, String.class);
        return ACCESS_TOKEN_TYPE.equals(tokenType);
    }

    private static class TokenRevocationInfo {
        private final Date revokedAt;
        private final String reason;

        public TokenRevocationInfo(String reason) {
            this.revokedAt = new Date();
            this.reason = reason;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() - revokedAt.getTime() > TOKEN_REVOCATION_WINDOW;
        }
    }
}