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
    @Size(max = 255, message = "Email cannot exceed 255 characters")
    @Column(nullable = false, name = "email", unique = true)
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$", 
            message = "Password must contain at least one digit, one lowercase letter, one uppercase letter, and one special character")
    @Column(nullable = false, name = "password")
    private String password;

    @Column(nullable = false, name = "is_active")
    @Builder.Default
    private boolean isActive = true;

    @Column(nullable = false, name = "is_locked")
    @Builder.Default
    private boolean isLocked = false;

    @Column(nullable = false, name = "created_at", updatable = false)
    private Timestamp createdAt;

    @Column(name = "last_login_at")
    private Timestamp lastLoginAt;

    @Column(name = "failed_login_attempts")
    @Builder.Default
    private int failedLoginAttempts = 0;

    @Column(name = "last_failed_login")
    private Timestamp lastFailedLogin;

    @Column(name = "password_changed_at")
    private Timestamp passwordChangedAt;

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<RefreshToken> refreshTokens = new ArrayList<>();

    public void addRefreshToken(RefreshToken refreshToken) {
        if (refreshToken != null) {
            refreshTokens.add(refreshToken);
            refreshToken.setUser(this);
        }
    }

    public void removeRefreshToken(RefreshToken refreshToken) {
        if (refreshToken != null) {
            refreshTokens.remove(refreshToken);
            refreshToken.setUser(null);
        }
    }

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<EmailToken> emailTokens = new ArrayList<>();

    public void addEmailToken(EmailToken emailToken) {
        if (emailToken != null) {
            emailTokens.add(emailToken);
            emailToken.setUser(this);
        }
    }

    public void removeEmailToken(EmailToken emailToken) {
        if (emailToken != null) {
            emailTokens.remove(emailToken);
            emailToken.setUser(null);
        }
    }

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<OauthProvider> oauthProviders = new ArrayList<>();

    public void addOauthProvider(OauthProvider oauthProvider) {
        if (oauthProvider != null) {
            oauthProviders.add(oauthProvider);
            oauthProvider.setUser(this);
        }
    }

    public void removeOauthProvider(OauthProvider oauthProvider) {
        if (oauthProvider != null) {
            oauthProviders.remove(oauthProvider);
            oauthProvider.setUser(null);
        }
    }

    @OneToMany(mappedBy = "user", cascade = {CascadeType.ALL}, orphanRemoval = true)
    @Builder.Default
    private List<AuditLog> auditLogs = new ArrayList<>();

    public void addAuditLog(AuditLog auditLog) {
        if (auditLog != null) {
            auditLogs.add(auditLog);
            auditLog.setUser(this);
        }
    }

    public void removeAuditLog(AuditLog auditLog) {
        if (auditLog != null) {
            auditLogs.remove(auditLog);
            auditLog.setUser(null);
        }
    }

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();

    @PrePersist
    protected void onCreate() {
        createdAt = new Timestamp(System.currentTimeMillis());
        isActive = true;
        isLocked = false;
        failedLoginAttempts = 0;
    }

    @PreUpdate
    protected void onUpdate() {
        if (username != null) {
            username = username.trim();
        }
        if (email != null) {
            email = email.trim().toLowerCase();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        User user = (User) o;
        return id != null && id.equals(user.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
