package com.codejam.codex.authzen.utils;

import com.codejam.codex.authzen.dtos.inputs.*;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

public class ValidationUtil {
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,20}$");
    private static final Pattern ROLE_NAME_PATTERN = Pattern.compile("^ROLE_[A-Z_]+$");
    private static final String[] ALLOWED_OAUTH_PROVIDERS = {"google", "github", "facebook"};

    public void validateRegisterRequest(RegisterRequest request) {
        if (!StringUtils.hasText(request.getUsername())) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        validateUsername(request.getUsername());
        if (!StringUtils.hasText(request.getEmail())) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        validateEmail(request.getEmail());
        if (!StringUtils.hasText(request.getPassword())) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        validatePassword(request.getPassword());
    }

    public void validateLoginRequest(LoginRequest request) {
        if (!StringUtils.hasText(request.getEmail())) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        validateEmail(request.getEmail());
        if (!StringUtils.hasText(request.getPassword())) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
    }

    public void validateOAuthProvider(String provider) {
        if (!StringUtils.hasText(provider)) {
            throw new IllegalArgumentException("OAuth provider cannot be empty");
        }
        boolean isValid = false;
        for (String allowedProvider : ALLOWED_OAUTH_PROVIDERS) {
            if (allowedProvider.equalsIgnoreCase(provider)) {
                isValid = true;
                break;
            }
        }
        if (!isValid) {
            throw new IllegalArgumentException("Invalid OAuth provider. Allowed providers are: " + String.join(", ", ALLOWED_OAUTH_PROVIDERS));
        }
    }

    public void validateEmail(String email) {
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("Invalid email format");
        }
    }

    public void validatePassword(String password) {
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException("Password must be at least 8 characters long and contain at least one digit, one lowercase letter, one uppercase letter, and one special character");
        }
    }

    public void validatePasswordResetRequest(PasswordResetRequest request) {
        if (!StringUtils.hasText(request.getResetToken())) {
            throw new IllegalArgumentException("Reset token cannot be empty");
        }
        if (!StringUtils.hasText(request.getNewPassword())) {
            throw new IllegalArgumentException("New password cannot be empty");
        }
        validatePassword(request.getNewPassword());
    }

    public void validateUsername(String username) {
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException("Username must be 3-20 characters long and contain only letters, numbers, and underscores");
        }
    }

    public void validateUpdateUserRequest(UpdateUserRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Update request cannot be null");
        }
        if (request.getEmail() != null) {
            validateEmail(request.getEmail());
        }
        if (request.getPassword() != null) {
            validatePassword(request.getPassword());
        }
        if (request.getUsername() != null) {
            validateUsername(request.getUsername());
        }
    }

    public void validateRoleUpdateRequest(RoleUpdateRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Role update request cannot be null");
        }
        if (request.getRoles() == null || request.getRoles().isEmpty()) {
            throw new IllegalArgumentException("Roles cannot be empty");
        }
        for (String role : request.getRoles()) {
            if (!StringUtils.hasText(role)) {
                throw new IllegalArgumentException("Role name cannot be empty");
            }
            if (!ROLE_NAME_PATTERN.matcher(role).matches()) {
                throw new IllegalArgumentException("Invalid role name format. Must start with 'ROLE_' and contain only uppercase letters and underscores");
            }
        }
    }

    public void validateRoleRequest(RoleRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Role request cannot be null");
        }
        if (!StringUtils.hasText(request.getName())) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }
        if (!ROLE_NAME_PATTERN.matcher(request.getName()).matches()) {
            throw new IllegalArgumentException("Invalid role name format. Must start with 'ROLE_' and contain only uppercase letters and underscores");
        }
        if (!StringUtils.hasText(request.getDescription())) {
            throw new IllegalArgumentException("Role description cannot be empty");
        }
    }

    public void validateDelegateRequest(DelegateRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Delegate request cannot be null");
        }
        if (!StringUtils.hasText(request.getTargetUsername())) {
            throw new IllegalArgumentException("Target username cannot be empty");
        }
        validateUsername(request.getTargetUsername());
        if (request.getPermissions() == null || request.getPermissions().isEmpty()) {
            throw new IllegalArgumentException("Permissions cannot be empty");
        }
        for (String permission : request.getPermissions()) {
            if (!StringUtils.hasText(permission)) {
                throw new IllegalArgumentException("Permission name cannot be empty");
            }
        }
    }
} 