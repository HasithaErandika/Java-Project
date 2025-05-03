package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import com.codejam.codex.authzen.endpoint.UserEndpoint;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * Handles secured endpoints related to authenticated user actions such as
 * viewing/updating profile, refreshing tokens, and logout.
 */
@RestController
@RequestMapping(ApiEndpoint.USER)
@PreAuthorize("hasRole('USER')")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final AuthEndpoint authEndpoint;
    private final UserEndpoint userEndpoint;

    @Autowired
    public UserController(AuthEndpoint authEndpoint, UserEndpoint userEndpoint) {
        this.authEndpoint = authEndpoint;
        this.userEndpoint = userEndpoint;
    }

    /**
     * Retrieves the authenticated user's profile.
     *
     * @param request HttpServletRequest with access token
     * @return User profile in standardized response format
     */
    @PreAuthorize("hasAuthority('VIEW_USER')")
    @GetMapping(ApiEndpoint.AUTH_ME)
    public ResponseEntity<AuthzenResponse<UserResponse>> getProfile(HttpServletRequest request) {
        try {
            if (!authEndpoint.isAuthenticated(request)) {
                logger.warn("Unauthorized access attempt to get profile");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token"));
            }

            String username = authEndpoint.getUsername(request);
            if (username == null) {
                logger.warn("Failed to extract username from token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Unauthorized: Cannot extract username"));
            }

            UserResponse profile = userEndpoint.getProfile(username);
            if (profile == null) {
                logger.error("Failed to retrieve profile for user: {}", username);
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new AuthzenResponse<>(null, false, "Profile not found"));
            }

            AuthzenResponse<UserResponse> response = new AuthzenResponse<>(profile);
            response.setMessage("User profile retrieved successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error retrieving user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred while retrieving profile"));
        }
    }

    /**
     * Updates the authenticated user's profile.
     *
     * @param request       HttpServletRequest with access token
     * @param updateRequest Updated user information
     * @return Success message
     */
    @PreAuthorize("hasAuthority('UPDATE_USER')")
    @PutMapping(ApiEndpoint.AUTH_UPDATE)
    public ResponseEntity<AuthzenResponse<UpdateUserResponse>> updateProfile(
            HttpServletRequest request,
            @Valid @RequestBody UpdateUserRequest updateRequest
    ) {
        try {
            if (!authEndpoint.isAuthenticated(request)) {
                logger.warn("Unauthorized access attempt to update profile");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Unauthorized"));
            }

            String username = authEndpoint.getUsername(request);
            UpdateUserResponse updateUserResponse = userEndpoint.updateUser(username, updateRequest);

            if (updateUserResponse == null) {
                logger.error("Failed to update profile for user: {}", username);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new AuthzenResponse<>(null, false, "Failed to update profile"));
            }

            AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(updateUserResponse);
            response.setMessage("User updated successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error updating user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred while updating profile"));
        }
    }

    /**
     * Logs out the authenticated user.
     * Note: This is a stateless operation unless token blacklisting is implemented.
     *
     * @param request HttpServletRequest with access token
     * @return Success message
     */
    @PreAuthorize("hasAuthority('USER_LOGOUT')")
    @PostMapping(ApiEndpoint.AUTH_LOGOUT)
    public ResponseEntity<AuthzenResponse<Object>> logout(HttpServletRequest request) {
        try {
            if (!authEndpoint.isAuthenticated(request)) {
                logger.warn("Unauthorized access attempt to logout");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Unauthorized"));
            }

            boolean blacklisted = authEndpoint.blacklistToken(request);

            if (blacklisted) {
                AuthzenResponse<Object> response = new AuthzenResponse<>();
                response.setMessage("User logged out successfully");
                return ResponseEntity.ok(response);
            } else {
                logger.error("Failed to blacklist token");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new AuthzenResponse<>(null, false, "Failed to blacklist token"));
            }
        } catch (Exception e) {
            logger.error("Error during logout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "An error occurred during logout"));
        }
    }
}