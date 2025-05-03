package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.*;
import com.codejam.codex.authzen.dtos.outputs.LoginResponse;
import com.codejam.codex.authzen.dtos.outputs.RegisterResponse;
import com.codejam.codex.authzen.dtos.outputs.TokenResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.*;
import com.codejam.codex.authzen.repositories.*;
import com.codejam.codex.authzen.utils.EmailUtil;
import com.codejam.codex.authzen.utils.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final JwtService jwtService;
    private final UserService userService;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final EmailUtil emailUtil;
    private final EmailTokenRepository emailTokenRepository;
    private final OauthProviderRepository oauthProviderRepository;
    private final OAuthService oAuthService;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final Set<String> blacklistedTokens = new HashSet<>();

    @Autowired
    public AuthService(JwtService jwtService, UserService userService, UserRepository userRepository,
                      BCryptPasswordEncoder passwordEncoder, EmailUtil emailUtil, EmailTokenRepository emailTokenRepository, 
                      OauthProviderRepository oauthProviderRepository, OAuthService oAuthService, 
                      RoleRepository roleRepository, RefreshTokenRepository refreshTokenRepository) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailUtil = emailUtil;
        this.emailTokenRepository = emailTokenRepository;
        this.oauthProviderRepository = oauthProviderRepository;
        this.oAuthService = oAuthService;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * Registers a new user.
     *
     * @param request The registration request containing user details.
     * @return RegisterResponse with user details and verification status.
     */
    public RegisterResponse register(RegisterRequest request) {
        UserResponse userResponse = registerUser(request);
        return RegisterResponse.builder()
                .id(userResponse.getId())
                .username(userResponse.getUsername())
                .email(userResponse.getEmail())
                .emailVerified(false)
                .roles(new ArrayList<>(userResponse.getRoles()))
                .verificationToken(UUID.randomUUID().toString())
                .message("Registration successful. Please verify your email.")
                .build();
    }

    /**
     * Authenticates a user and returns login response.
     *
     * @param request The login request containing user credentials.
     * @return LoginResponse with tokens and user details, or null if authentication fails.
     */
    public LoginResponse login(LoginRequest request) {
        try {
            TokenResponse tokenResponse = authenticateUser(request);
            if (tokenResponse == null) {
                return null;
            }
            UserResponse userResponse = getUserDetails(request.getEmail());
            if (userResponse == null) {
                return null;
            }
            return LoginResponse.builder()
                    .accessToken(tokenResponse.getAccessToken())
                    .refreshToken(tokenResponse.getRefreshToken())
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .username(userResponse.getUsername())
                    .email(userResponse.getEmail())
                    .roles(new ArrayList<>(userResponse.getRoles()))
                    .permissions(new ArrayList<>(userResponse.getPermissions()))
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Authenticates a user via OAuth and returns login response.
     *
     * @param provider The OAuth provider (e.g., "google", "github")
     * @param code The authorization code from the OAuth provider
     * @return LoginResponse with OAuth tokens and user details, or null if authentication fails.
     */
    public LoginResponse oauthLogin(String provider, String code) {
        try {
            OAuthRequest oAuthRequest = new OAuthRequest();
            oAuthRequest.setProvider(provider);
            oAuthRequest.setOauthToken(code);
            TokenResponse tokenResponse = authenticateOAuth(oAuthRequest);
            if (tokenResponse == null) {
                return null;
            }
            
            // Extract username from access token
            String username = jwtService.extractUsername(tokenResponse.getAccessToken());
            if (username == null) {
                return null;
            }
            
            UserResponse userResponse = getUserDetails(username);
            if (userResponse == null) {
                return null;
            }
            
            return LoginResponse.builder()
                    .accessToken(tokenResponse.getAccessToken())
                    .refreshToken(tokenResponse.getRefreshToken())
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .username(userResponse.getUsername())
                    .email(userResponse.getEmail())
                    .roles(new ArrayList<>(userResponse.getRoles()))
                    .permissions(new ArrayList<>(userResponse.getPermissions()))
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sends a password reset email to the user.
     *
     * @param email The user's email address.
     * @return Success message if email was sent, error message otherwise.
     */
    public String requestPasswordReset(String email) {
        try {
            ResetRequest resetRequest = new ResetRequest();
            resetRequest.setEmail(email);
            boolean success = sendPasswordResetEmail(resetRequest);
            return success ? "Password reset email sent successfully" : "Failed to send password reset email";
        } catch (Exception e) {
            return "Failed to send password reset email";
        }
    }

    /**
     * Resets the user's password using a provided reset token.
     *
     * @param request The reset password request containing the token and new password.
     * @return Success message if password was reset, error message otherwise.
     */
    public String resetPassword(PasswordResetRequest request) {
        try {
            ResetPasswordRequest resetPasswordRequest = new ResetPasswordRequest();
            resetPasswordRequest.setToken(request.getResetToken());
            resetPasswordRequest.setNewPassword(request.getNewPassword());
            boolean success = resetUserPassword(resetPasswordRequest);
            return success ? "Password reset successful" : "Failed to reset password";
        } catch (Exception e) {
            return "Failed to reset password";
        }
    }

    /**
     * Refreshes access and refresh tokens using the provided refresh token.
     *
     * @param request The refresh token request containing the refresh token.
     * @return LoginResponse with new tokens and user details, or null if refresh fails.
     */
    public LoginResponse refreshToken(RefreshTokenRequest request) {
        try {
            TokenResponse tokenResponse = refreshToken(request.getRefreshToken());
            if (tokenResponse == null) {
                return null;
            }
            
            // Extract username from access token
            String username = jwtService.extractUsername(tokenResponse.getAccessToken());
            if (username == null) {
                return null;
            }
            
            UserResponse userResponse = getUserDetails(username);
            if (userResponse == null) {
                return null;
            }
            
            return LoginResponse.builder()
                    .accessToken(tokenResponse.getAccessToken())
                    .refreshToken(tokenResponse.getRefreshToken())
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .username(userResponse.getUsername())
                    .email(userResponse.getEmail())
                    .roles(new ArrayList<>(userResponse.getRoles()))
                    .permissions(new ArrayList<>(userResponse.getPermissions()))
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Registers a new user.
     *
     * @param request The registration request containing user details.
     * @return true if registration was successful, false otherwise.
     */
    public UserResponse registerUser(RegisterRequest request) {
        // Check if username or email already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        List<Role> roles = roleRepository.findByName("ROLE_USER");
        if (roles.isEmpty()) {
            throw new RuntimeException("Default role not found: ROLE_USER");
        }
        Role userRole = roles.get(0);

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setActive(true);
        user.setLocked(false);
        user.setCreatedAt(new Timestamp(System.currentTimeMillis()));
        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(null);
        
        // Create UserRole mapping
        UserRole userRoleMapping = new UserRole();
        userRoleMapping.setUser(user);
        userRoleMapping.setRole(userRole);
        user.getUserRoles().add(userRoleMapping);
        
        // Save the user
        user = userRepository.save(user);
        
        // Get permissions
        List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
        
        // Create and return UserResponse
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getUserRoles().stream()
                        .map(userRole1 -> userRole1.getRole().getName())
                        .collect(Collectors.toSet()))
                .permissions(permissionNames)
                .build();
    }

    /**
     * Authenticates a user and issues an access token.
     *
     * @param request The login request containing user credentials.
     * @return Access token if authentication is successful, null otherwise.
     */
    public TokenResponse authenticateUser(LoginRequest request) {
        try {
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            
            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
                if (user.getFailedLoginAttempts() >= 5) {
                    user.setLocked(true);
                }
                userRepository.save(user);
                throw new RuntimeException("Invalid password");
            }
            
            if (!user.isActive()) {
                throw new RuntimeException("Account is not active");
            }
            
            if (user.isLocked()) {
                throw new RuntimeException("Account is locked");
            }
            
            // Reset failed login attempts and update last login
            user.setFailedLoginAttempts(0);
            user.setLastLoginAt(new Timestamp(System.currentTimeMillis()));
            userRepository.save(user);
            
            // Get user details
            UserResponse userResponse = userService.loadUserByUsername(user.getEmail());
            if (userResponse == null) {
                throw new RuntimeException("Failed to load user details");
            }
            
            // Generate tokens
            String accessToken = jwtService.generateAccessToken(userResponse);
            String refreshToken = jwtService.generateRefreshToken(userResponse);
            
            // Save refresh token
            saveRefreshToken(user, refreshToken);
            
            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Handles OAuth login and generates OAuth token.
     *
     * @param request The OAuth login request containing OAuth credentials.
     * @return OAuth token if successful, null otherwise.
     */
    public TokenResponse authenticateOAuth(OAuthRequest request) {
        try {
            // Get user info from OAuth provider
            UserResponse userInfo;
            if ("github".equalsIgnoreCase(request.getProvider())) {
                String oAuthAccessToken = oAuthService.getGithubAccessToken(request.getOauthToken());
                Map<String, Object> githubUser = oAuthService.getGithubUser(oAuthAccessToken);
                
                userInfo = UserResponse.builder()
                        .username((String) githubUser.get("login"))
                        .email((String) githubUser.get("email"))
                        .build();
            } else {
                throw new RuntimeException("Unsupported OAuth provider: " + request.getProvider());
            }
            
            if (userInfo == null) {
                throw new RuntimeException("Failed to get user info from OAuth provider");
            }
            
            // Find or create user
            User user = userRepository.findByEmail(userInfo.getEmail())
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setUsername(userInfo.getUsername());
                        newUser.setEmail(userInfo.getEmail());
                        newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
                        newUser.setActive(true);
                        newUser.setLocked(false);
                        newUser.setCreatedAt(new Timestamp(System.currentTimeMillis()));
                        newUser.setFailedLoginAttempts(0);
                        newUser.setLastLoginAt(null);
                        
                        // Set default role
                        List<Role> roles = roleRepository.findByName("ROLE_USER");
                        if (!roles.isEmpty()) {
                            UserRole userRoleMapping = new UserRole();
                            userRoleMapping.setUser(newUser);
                            userRoleMapping.setRole(roles.get(0));
                            newUser.getUserRoles().add(userRoleMapping);
                        }
                        
                        return userRepository.save(newUser);
                    });
            
            // Get user details
            UserResponse userResponse = userService.loadUserByUsername(user.getEmail());
            if (userResponse == null) {
                throw new RuntimeException("Failed to load user details");
            }
            
            // Generate tokens
            String accessToken = jwtService.generateAccessToken(userResponse);
            String refreshToken = jwtService.generateRefreshToken(userResponse);
            
            // Save refresh token
            saveRefreshToken(user, refreshToken);
            
            return TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Sends a password reset email to the user.
     *
     * @param request The reset request containing the user's email.
     * @return true if email was sent successfully, false otherwise.
     */
    public boolean sendPasswordResetEmail(ResetRequest request) {
        try {
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Create reset token
            String resetToken = UUID.randomUUID().toString();
            EmailToken emailToken = new EmailToken();
            emailToken.setToken(resetToken);
            emailToken.setUser(user);
            emailToken.setPurpose("PASSWORD_RESET");
            emailToken.setExpiresAt(Timestamp.from(Instant.now().plus(15, ChronoUnit.MINUTES)));
            emailTokenRepository.save(emailToken);

            // Send email
            String resetLink = "http://localhost:8080/reset-password?token=" + resetToken;
            String subject = "Password Reset Request";
            String body = "Click the following link to reset your password: ${RESET_LINK}";
            
            return emailUtil.sendPasswordResetEmail(user.getEmail(), subject, body, resetLink);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Resets the user's password using the provided token.
     *
     * @param request The reset password request containing token and new password.
     * @return true if the password was successfully reset, false otherwise.
     */
    public boolean resetUserPassword(ResetPasswordRequest request) {
        try {
            // Find email token
            EmailToken emailToken = emailTokenRepository.findByToken(request.getToken())
                    .orElseThrow(() -> new RuntimeException("Invalid reset token"));

            // Check if token is expired
            if (emailToken.getExpiresAt().before(Timestamp.from(Instant.now()))) {
                emailTokenRepository.delete(emailToken);
                throw new RuntimeException("Reset token has expired");
            }

            // Check if token is for password reset
            if (!"PASSWORD_RESET".equals(emailToken.getPurpose())) {
                throw new RuntimeException("Invalid token purpose");
            }

            // Update user password
            User user = emailToken.getUser();
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            user.setPasswordChangedAt(Timestamp.from(Instant.now()));
            userRepository.save(user);

            // Delete used token
            emailTokenRepository.delete(emailToken);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Checks if the user is authenticated by validating the token from the request.
     *
     * @param request The HTTP request containing the token.
     * @return true if the user is authenticated, false otherwise.
     */
    public boolean isAuthenticated(HttpServletRequest request) {
        final String token = extractTokenFromHeader(request);
        if (token == null || isBlacklisted(token)) {
            return false;
        }
        
        if (!jwtService.isTokenValid(token)) {
            return false;
        }

        final String username = jwtService.extractUsername(token);
        if (username == null) {
            return false;
        }
        
        UserResponse userDetails = userService.loadUserByUsername(username);
        return userDetails != null && jwtService.isTokenValid(token, userDetails);
    }

    /**
     * Extracts the token from the HTTP request header.
     *
     * @param request The HTTP request.
     * @return The token if present, null otherwise.
     */
    private String extractTokenFromHeader(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Retrieves the username from the token in the request.
     *
     * @param request The HTTP request containing the token.
     * @return The username extracted from the token, or null if the token is invalid.
     */
    public String getUsername(HttpServletRequest request) {
        final String token = extractTokenFromHeader(request);
        if (token == null || isBlacklisted(token)) {
            return null;
        }
        return jwtService.extractUsername(token);
    }

    /**
     * Retrieves user details from the username.
     *
     * @param username The username.
     * @return UserResponse with the user's details, or null if the user doesn't exist.
     */
    public UserResponse getUserDetails(String username) {
        try {
            return userService.loadUserByUsername(username);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Saves a refresh token for a user.
     *
     * @param user The user associated with the refresh token.
     * @param token The refresh token to be saved.
     */
    private void saveRefreshToken(User user, String token) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(token);
        refreshToken.setExpiresAt(Timestamp.from(Instant.now().plus(7, ChronoUnit.DAYS)));
        refreshTokenRepository.save(refreshToken);
    }

    /**
     * Refreshes an access token using a valid refresh token.
     *
     * @param refreshToken The refresh token to be used for refreshing the access token.
     * @return TokenResponse containing new access and refresh tokens.
     * @throws RuntimeException if the refresh token is expired or invalid.
     */
    public TokenResponse refreshToken(String refreshToken) {
        try {
            // Validate refresh token
            if (!jwtService.isTokenValid(refreshToken)) {
                throw new RuntimeException("Invalid refresh token");
            }

            // Extract username from token
            String username = jwtService.extractUsername(refreshToken);
            if (username == null) {
                throw new RuntimeException("Invalid refresh token");
            }

            // Get user details
            UserResponse userResponse = userService.loadUserByUsername(username);
            if (userResponse == null) {
                throw new RuntimeException("User not found");
            }

            // Generate new tokens
            String newAccessToken = jwtService.generateAccessToken(userResponse);
            String newRefreshToken = jwtService.generateRefreshToken(userResponse);

            // Save new refresh token
            User user = userRepository.findByEmail(userResponse.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            saveRefreshToken(user, newRefreshToken);

            return TokenResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Blacklists the token associated with the incoming request if valid and not already blacklisted.
     *
     * @param request HttpServletRequest containing the token to be blacklisted.
     * @return true if the token was successfully added to the blacklist; false if the token is invalid
     *         or already blacklisted.
     */
    public boolean blacklistToken(HttpServletRequest request) {
        final String token = extractTokenFromHeader(request);
        if (token == null) {
            return false;
        }

        // Validate token before blacklisting
        if (!jwtService.isTokenValid(token)) {
            return false;
        }

        if (!isBlacklisted(token)) {
            blacklistedTokens.add(token);
            return true;
        }
        return false;
    }

    /**
     * Checks if a token is blacklisted.
     *
     * @param token The token to check.
     * @return true if the token is blacklisted, false otherwise.
     */
    public boolean isBlacklisted(String token) {
        return token != null && blacklistedTokens.contains(token);
    }
}
