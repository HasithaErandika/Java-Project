package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.LoginRequest;
import com.codejam.codex.authzen.dtos.inputs.PasswordResetRequest;
import com.codejam.codex.authzen.dtos.inputs.RefreshTokenRequest;
import com.codejam.codex.authzen.dtos.inputs.RegisterRequest;
import com.codejam.codex.authzen.dtos.outputs.LoginResponse;
import com.codejam.codex.authzen.dtos.outputs.RegisterResponse;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import com.codejam.codex.authzen.services.RateLimiterService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * AuthController handles all authentication-related endpoints.
 * This includes user registration, login, password reset, and OAuth login.
 */
@RestController
@RequestMapping(ApiEndpoint.AUTH)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthEndpoint authEndpoint;
    private final RateLimiterService rateLimiterService;

    @Autowired
    public AuthController(AuthEndpoint authEndpoint, RateLimiterService rateLimiterService) {
        this.authEndpoint = authEndpoint;
        this.rateLimiterService = rateLimiterService;
    }

    @PostMapping(ApiEndpoint.AUTH_REGISTER)
    public ResponseEntity<AuthzenResponse<RegisterResponse>> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            if (!rateLimiterService.tryAcquire("register", registerRequest.getEmail())) {
                logger.warn("Rate limit exceeded for registration from IP: {}", registerRequest.getEmail());
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new AuthzenResponse<>(null, false, "Too many registration attempts. Please try again later."));
            }

            RegisterResponse registerResponse = authEndpoint.register(registerRequest);
            if (registerResponse == null) {
                logger.error("Failed to register user: {}", registerRequest.getEmail());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new AuthzenResponse<>(null, false, "Failed to register user"));
            }
            AuthzenResponse<RegisterResponse> response = new AuthzenResponse<>(registerResponse);
            response.setMessage("User registered successfully.");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error during user registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred during registration"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_LOGIN)
    public ResponseEntity<AuthzenResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            if (!rateLimiterService.tryAcquire("login", loginRequest.getEmail())) {
                logger.warn("Rate limit exceeded for login attempts from email: {}", loginRequest.getEmail());
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new AuthzenResponse<>(null, false, "Too many login attempts. Please try again later."));
            }

            LoginResponse loginResponse = authEndpoint.login(loginRequest);
            if (loginResponse == null) {
                logger.error("Failed to login user: {}", loginRequest.getEmail());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Invalid credentials"));
            }
            AuthzenResponse<LoginResponse> response = new AuthzenResponse<>(loginResponse);
            response.setMessage("User logged in successfully.");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error during user login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred during login"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_OAUTH)
    public ResponseEntity<AuthzenResponse<LoginResponse>> oauthLogin(@RequestParam("provider") String provider,
                                                                   @RequestParam("code") String code) {
        try {
            if (!rateLimiterService.tryAcquire("oauth_login", provider)) {
                logger.warn("Rate limit exceeded for OAuth login attempts from provider: {}", provider);
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new AuthzenResponse<>(null, false, "Too many OAuth login attempts. Please try again later."));
            }

            LoginResponse loginResponse = authEndpoint.oauthLogin(provider, code);
            if (loginResponse == null) {
                logger.error("Failed to login with OAuth provider: {}", provider);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "OAuth login failed"));
            }
            AuthzenResponse<LoginResponse> response = new AuthzenResponse<>(loginResponse);
            response.setMessage("OAuth login successful.");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error during OAuth login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred during OAuth login"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_RESET_REQUEST)
    public ResponseEntity<AuthzenResponse<String>> requestPasswordReset(@RequestParam("email") String email) {
        try {
            if (!rateLimiterService.tryAcquire("password_reset", email)) {
                logger.warn("Rate limit exceeded for password reset requests from email: {}", email);
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .body(new AuthzenResponse<>(null, false, "Too many password reset requests. Please try again later."));
            }

            String message = authEndpoint.requestPasswordReset(email);
            AuthzenResponse<String> response = new AuthzenResponse<>();
            response.setMessage(message);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error requesting password reset", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred while requesting password reset"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_RESET_PASSWORD)
    public ResponseEntity<AuthzenResponse<String>> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        try {
            String message = authEndpoint.resetPassword(request);
            AuthzenResponse<String> response = new AuthzenResponse<>();
            response.setMessage(message);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error resetting password", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred while resetting password"));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_REFRESH)
    public ResponseEntity<AuthzenResponse<LoginResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            LoginResponse loginResponse = authEndpoint.refreshToken(request);
            if (loginResponse == null) {
                logger.error("Failed to refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Invalid refresh token"));
            }
            AuthzenResponse<LoginResponse> response = new AuthzenResponse<>(loginResponse);
            response.setMessage("Token refreshed successfully.");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error refreshing token", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred while refreshing token"));
        }
    }
}