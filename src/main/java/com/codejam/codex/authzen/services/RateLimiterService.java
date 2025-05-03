package com.codejam.codex.authzen.services;

import org.springframework.stereotype.Service;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;

/**
 * Service for rate limiting requests based on different operations and identifiers.
 */
@Service
public class RateLimiterService {

    private final Cache<String, Integer> rateLimitCache;
    private static final int MAX_ATTEMPTS = 5;
    private static final int WINDOW_MINUTES = 15;

    public RateLimiterService() {
        this.rateLimitCache = Caffeine.newBuilder()
                .expireAfterWrite(WINDOW_MINUTES, TimeUnit.MINUTES)
                .build();
    }

    /**
     * Attempts to acquire a rate limit token for the given operation and identifier.
     *
     * @param operation The operation being rate limited (e.g., "login", "register")
     * @param identifier The identifier for rate limiting (e.g., username, email, IP)
     * @return true if the request is allowed, false if rate limit is exceeded
     */
    public boolean tryAcquire(String operation, String identifier) {
        String key = operation + ":" + identifier;
        Integer attempts = rateLimitCache.getIfPresent(key);
        
        if (attempts == null) {
            rateLimitCache.put(key, 1);
            return true;
        }
        
        if (attempts >= MAX_ATTEMPTS) {
            return false;
        }
        
        rateLimitCache.put(key, attempts + 1);
        return true;
    }

    /**
     * Resets the rate limit counter for the given operation and identifier.
     *
     * @param operation The operation being rate limited
     * @param identifier The identifier for rate limiting
     */
    public void reset(String operation, String identifier) {
        String key = operation + ":" + identifier;
        rateLimitCache.invalidate(key);
    }
} 