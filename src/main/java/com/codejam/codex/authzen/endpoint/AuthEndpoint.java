package com.codejam.codex.authzen.endpoint;

import com.codejam.codex.authzen.dtos.inputs.*;
import com.codejam.codex.authzen.dtos.outputs.LoginResponse;
import com.codejam.codex.authzen.dtos.outputs.RegisterResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.services.AuthService;
import com.codejam.codex.authzen.utils.ValidationUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Endpoint responsible for handling authentication-related logic such as
 * extracting username, validating authentication, and refreshing tokens.
 */
@Component
public class AuthEndpoint {

    private final AuthService authService;
    private final ValidationUtil validationUtil;

    @Autowired
    public AuthEndpoint(AuthService authService, ValidationUtil validationUtil) {
        this.authService = authService;
        this.validationUtil = validationUtil;
    }

    /**
     * Checks if the incoming request contains a valid access token.
     *
     * @param request HttpServletRequest
     * @return true if authenticated; false otherwise
     */
    public boolean isAuthenticated(HttpServletRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
        return authService.isAuthenticated(request);
    }

    /**
     * Extracts the username from a valid JWT access token in the request.
     *
     * @param request HttpServletRequest
     * @return Username or null if token is invalid
     */
    public String getUsername(HttpServletRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
        return authService.getUsername(request);
    }

    /**
     * Registers a new user.
     *
     * @param request The registration request containing user details.
     * @return RegisterResponse with user details and verification status.
     */
    public RegisterResponse register(RegisterRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Registration request cannot be null");
        }
        validationUtil.validateRegisterRequest(request);
        return authService.register(request);
    }

    /**
     * Authenticates a user and returns login response.
     *
     * @param request The login request containing user credentials.
     * @return LoginResponse with tokens and user details, or null if authentication fails.
     */
    public LoginResponse login(LoginRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Login request cannot be null");
        }
        validationUtil.validateLoginRequest(request);
        return authService.login(request);
    }

    /**
     * Authenticates a user via OAuth and returns login response.
     *
     * @param provider The OAuth provider (e.g., "google", "github")
     * @param code The authorization code from the OAuth provider
     * @return LoginResponse with OAuth tokens and user details, or null if authentication fails.
     */
    public LoginResponse oauthLogin(String provider, String code) {
        if (!StringUtils.hasText(provider)) {
            throw new IllegalArgumentException("OAuth provider cannot be empty");
        }
        if (!StringUtils.hasText(code)) {
            throw new IllegalArgumentException("Authorization code cannot be empty");
        }
        validationUtil.validateOAuthProvider(provider);
        return authService.oauthLogin(provider, code);
    }

    /**
     * Sends a password reset email to the user.
     *
     * @param email The user's email address.
     * @return Success message if email was sent, error message otherwise.
     */
    public String requestPasswordReset(String email) {
        if (!StringUtils.hasText(email)) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        validationUtil.validateEmail(email);
        return authService.requestPasswordReset(email);
    }

    /**
     * Resets the user's password using a provided reset token.
     *
     * @param request The reset password request containing the token and new password.
     * @return Success message if password was reset, error message otherwise.
     */
    public String resetPassword(PasswordResetRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Password reset request cannot be null");
        }
        validationUtil.validatePasswordResetRequest(request);
        return authService.resetPassword(request);
    }

    /**
     * Refreshes access and refresh tokens using the provided refresh token.
     *
     * @param request The refresh token request containing the refresh token.
     * @return LoginResponse with new tokens and user details, or null if refresh fails.
     */
    public LoginResponse refreshToken(RefreshTokenRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Refresh token request cannot be null");
        }
        if (!StringUtils.hasText(request.getRefreshToken())) {
            throw new IllegalArgumentException("Refresh token cannot be empty");
        }
        return authService.refreshToken(request);
    }

    /**
     * Blacklists a token to prevent further use.
     *
     * @param request HttpServletRequest containing the token to blacklist.
     * @return true if token was successfully blacklisted, false otherwise.
     */
    public boolean blacklistToken(HttpServletRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
        return authService.blacklistToken(request);
    }

    /**
     * Retrieves user details by username.
     *
     * @param username The username to look up.
     * @return UserResponse with user details, or null if user not found.
     */
    public UserResponse getUserDetails(String username) {
        if (!StringUtils.hasText(username)) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        return authService.getUserDetails(username);
    }
}