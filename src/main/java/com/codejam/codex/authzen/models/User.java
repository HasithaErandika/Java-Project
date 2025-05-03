package com.codejam.codex.authzen.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@ToString
@Table(name = "users", uniqueConstraints = {
    @UniqueConstraint(columnNames = "username"),
    @UniqueConstraint(columnNames = "email")
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
    @Column(nullable = false, name = "username", unique = true)
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    @Column(nullable = false, name = "email", unique = true)
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$", 
            message = "Password must contain at least one digit, one lowercase letter, one uppercase letter, and one special character")
    @Column(nullable = false, name = "password")
    private String password;

    @Column(nullable = false, name = "is_active")
    private boolean isActive;

    @Column(nullable = false, name = "is_locked")
    private boolean isLocked;

    @Column(nullable = false, name = "created_at")
    private Timestamp createdAt;

    @Column(name = "last_login_at")
    private Timestamp lastLoginAt;

    @Column(name = "failed_login_attempts")
    private int failedLoginAttempts;

    @Column(name = "last_failed_login")
    private Timestamp lastFailedLogin;

    @Column(name = "password_changed_at")
    private Timestamp passwordChangedAt;

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<RefreshToken> refreshTokens = new ArrayList<>();

    public void addRefreshToken(RefreshToken refreshToken) {
        refreshTokens.add(refreshToken);
        refreshToken.setUser(this);
    }

    public void removeRefreshToken(RefreshToken refreshToken) {
        refreshTokens.remove(refreshToken);
        refreshToken.setUser(null);
    }

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<EmailToken> emailTokens = new ArrayList<>();

    public void addEmailTokens(EmailToken emailToken) {
        emailTokens.add(emailToken);
        emailToken.setUser(this);
    }

    public void removeEmailToken(EmailToken emailToken) {
        emailTokens.remove(emailToken);
        emailToken.setUser(null);
    }

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<OauthProvider> oauthProviders = new ArrayList<>();

    public void addOauthProvider(OauthProvider oauthProvider) {
        oauthProviders.add(oauthProvider);
        oauthProvider.setUser(this);
    }

    public void removeOauthProvider(OauthProvider oauthProvider) {
        oauthProviders.remove(oauthProvider);
        oauthProvider.setUser(null);
    }

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<AuditLog> auditLogs = new ArrayList<>();

    public void addAuditLog(AuditLog auditLog) {
        auditLogs.add(auditLog);
        auditLog.setUser(this);
    }

    public void removeAuditLog(AuditLog auditLog) {
        auditLogs.remove(auditLog);
        auditLog.setUser(null);
    }

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();
}
