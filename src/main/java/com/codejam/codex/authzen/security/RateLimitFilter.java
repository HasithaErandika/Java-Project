package com.codejam.codex.authzen.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    @Value("${app.rate-limit.max-requests}")
    private int maxRequests;

    @Value("${app.rate-limit.window-seconds}")
    private int windowSeconds;

    private final Map<String, RequestCounter> requestCounters = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String clientIp = getClientIp(request);
        String path = request.getRequestURI();

        // Only apply rate limiting to authentication endpoints
        if (isAuthenticationEndpoint(path)) {
            RequestCounter counter = requestCounters.computeIfAbsent(clientIp, k -> new RequestCounter());
            
            if (!counter.isAllowed()) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.getWriter().write("Too many requests. Please try again later.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private boolean isAuthenticationEndpoint(String path) {
        return path.contains("/api/authenticate/auth/login") ||
               path.contains("/api/authenticate/auth/register") ||
               path.contains("/api/authenticate/auth/reset-request");
    }

    private class RequestCounter {
        private final Instant windowStart;
        private int count;

        public RequestCounter() {
            this.windowStart = Instant.now();
            this.count = 1;
        }

        public boolean isAllowed() {
            if (Duration.between(windowStart, Instant.now()).getSeconds() > windowSeconds) {
                count = 1;
                return true;
            }
            if (count >= maxRequests) {
                return false;
            }
            count++;
            return true;
        }
    }
} 