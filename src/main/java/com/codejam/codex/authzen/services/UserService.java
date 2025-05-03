package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.repositories.UserRepository;
import com.codejam.codex.authzen.utils.JwtService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = TimeUnit.MINUTES.toMillis(30);
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$"
    );
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,20}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final Map<String, FailedLoginAttempt> failedAttempts = new ConcurrentHashMap<>();

    private static class FailedLoginAttempt {
        private int attempts;
        private long lastAttemptTime;
        private boolean locked;

        public FailedLoginAttempt() {
            this.attempts = 0;
            this.lastAttemptTime = System.currentTimeMillis();
            this.locked = false;
        }

        public void incrementAttempts() {
            attempts++;
            lastAttemptTime = System.currentTimeMillis();
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                locked = true;
            }
        }

        public boolean isLocked() {
            if (locked && System.currentTimeMillis() - lastAttemptTime > LOCK_TIME_DURATION) {
                locked = false;
                attempts = 0;
            }
            return locked;
        }

        public void reset() {
            attempts = 0;
            locked = false;
            lastAttemptTime = System.currentTimeMillis();
        }
    }

    private boolean isValidPassword(String password) {
        return password != null && 
               PASSWORD_PATTERN.matcher(password).matches();
    }

    private boolean isValidUsername(String username) {
        return username != null && 
               USERNAME_PATTERN.matcher(username).matches();
    }

    private boolean isValidEmail(String email) {
        return email != null && 
               EMAIL_PATTERN.matcher(email).matches();
    }

    public UserResponse loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        if (!StringUtils.hasText(usernameOrEmail)) {
            throw new UsernameNotFoundException("Username/email cannot be empty");
        }

        try {
            User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with username/email: " + usernameOrEmail));

            if (!user.isActive()) {
                throw new UsernameNotFoundException("User account is not active");
            }

            if (user.isLocked()) {
                throw new UsernameNotFoundException("User account is locked");
            }

            Set<String> roles = user.getUserRoles()
                    .stream()
                    .map(userRole -> userRole.getRole().getName())
                    .collect(Collectors.toSet());

            List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());

            return UserResponse.builder()
                    .id(user.getId())
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .roles(roles)
                    .permissions(permissionNames)
                    .build();
        } catch (UsernameNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new UsernameNotFoundException("Error loading user: " + e.getMessage());
        }
    }

    public UserResponse getProfile(String username) {
        if (!StringUtils.hasText(username)) {
            throw new RuntimeException("Username cannot be empty");
        }

        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
            
            if (!user.isActive()) {
                throw new RuntimeException("User account is not active");
            }

            if (user.isLocked()) {
                throw new RuntimeException("User account is locked");
            }

            List<String> permissionNames = userRepository.findPermissionNamesByUsername(username);
            return UserResponse.fromEntity(user, permissionNames);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error getting user profile: " + e.getMessage());
        }
    }

    @Transactional
    public UpdateUserResponse updateUser(String username, UpdateUserRequest updateRequest) {
        if (!StringUtils.hasText(username)) {
            throw new RuntimeException("Username cannot be empty");
        }

        if (updateRequest == null) {
            throw new RuntimeException("Update request cannot be null");
        }

        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found with username: " + username));

            if (!user.isActive()) {
                throw new RuntimeException("Cannot update inactive user account");
            }

            if (user.isLocked()) {
                throw new RuntimeException("Cannot update locked user account");
            }

            if (updateRequest.getUsername() != null && !updateRequest.getUsername().isBlank()) {
                if (!updateRequest.getUsername().equals(username) && 
                    userRepository.existsByUsername(updateRequest.getUsername())) {
                    throw new RuntimeException("Username already exists");
                }
                user.setUsername(updateRequest.getUsername());
            }

            if (updateRequest.getEmail() != null && !updateRequest.getEmail().isBlank()) {
                if (!updateRequest.getEmail().equals(user.getEmail()) && 
                    userRepository.existsByEmail(updateRequest.getEmail())) {
                    throw new RuntimeException("Email already exists");
                }
                user.setEmail(updateRequest.getEmail());
            }

            if (updateRequest.getPassword() != null && !updateRequest.getPassword().isBlank()) {
                if (updateRequest.getPassword().length() < 8) {
                    throw new RuntimeException("Password must be at least 8 characters long");
                }
                user.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
                user.setPasswordChangedAt(new java.sql.Timestamp(System.currentTimeMillis()));
            }

            User updatedUser = userRepository.save(user);
            return UpdateUserResponse.fromEntity(updatedUser);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error updating user: " + e.getMessage());
        }
    }

    public boolean authenticate(String username, String password) {
        if (!isValidUsername(username) || password == null || password.trim().isEmpty()) {
            logger.error("Invalid credentials format");
            return false;
        }

        FailedLoginAttempt attempt = failedAttempts.computeIfAbsent(username, k -> new FailedLoginAttempt());
        if (attempt.isLocked()) {
            logger.warn("Account locked for user: {}", username);
            return false;
        }

        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            if (!user.isActive()) {
                logger.error("User account is not active: {}", username);
                return false;
            }

            if (passwordEncoder.matches(password, user.getPassword())) {
                attempt.reset();
                return true;
            }

            attempt.incrementAttempts();
            logger.warn("Failed login attempt for user: {}", username);
            return false;
        } catch (Exception e) {
            attempt.incrementAttempts();
            logger.error("Authentication error for user {}: {}", username, e.getMessage());
            return false;
        }
    }

    public void lockAccount(String username) {
        if (isValidUsername(username)) {
            FailedLoginAttempt attempt = failedAttempts.computeIfAbsent(username, k -> new FailedLoginAttempt());
            attempt.incrementAttempts();
            logger.warn("Account locked for user: {}", username);
        }
    }

    public void unlockAccount(String username) {
        if (isValidUsername(username)) {
            FailedLoginAttempt attempt = failedAttempts.get(username);
            if (attempt != null) {
                attempt.reset();
                logger.info("Account unlocked for user: {}", username);
            }
        }
    }

    public boolean isAccountLocked(String username) {
        if (!isValidUsername(username)) {
            return true;
        }
        FailedLoginAttempt attempt = failedAttempts.get(username);
        return attempt != null && attempt.isLocked();
    }
}
