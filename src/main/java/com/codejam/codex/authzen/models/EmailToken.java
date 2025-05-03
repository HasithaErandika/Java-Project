package com.codejam.codex.authzen.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.sql.Timestamp;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@ToString
@Table(name = "email_tokens", uniqueConstraints = {
    @UniqueConstraint(columnNames = "token")
})
public class EmailToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull(message = "User is required")
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    @ToString.Exclude
    private User user;

    @NotBlank(message = "Purpose is required")
    @Size(max = 50, message = "Purpose cannot exceed 50 characters")
    @Pattern(regexp = "^(PASSWORD_RESET|EMAIL_VERIFICATION)$", message = "Purpose must be PASSWORD_RESET or EMAIL_VERIFICATION")
    @Column(nullable = false)
    private String purpose;

    @NotBlank(message = "Token is required")
    @Column(nullable = false, unique = true)
    private String token;

    @NotNull(message = "Expiration time is required")
    @Column(name = "expires_at", nullable = false)
    private Timestamp expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Timestamp createdAt;

    @Column(name = "used_at")
    private Timestamp usedAt;

    @Column(nullable = false)
    @Builder.Default
    private boolean used = false;

    @PrePersist
    protected void onCreate() {
        createdAt = new Timestamp(System.currentTimeMillis());
        if (purpose != null) {
            purpose = purpose.trim().toUpperCase();
        }
        if (token != null) {
            token = token.trim();
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("Expiration time is required");
        }
    }

    @PreUpdate
    protected void onUpdate() {
        if (purpose != null) {
            purpose = purpose.trim().toUpperCase();
        }
        if (token != null) {
            token = token.trim();
        }
    }

    public boolean isExpired() {
        return expiresAt.before(new Timestamp(System.currentTimeMillis()));
    }

    public boolean isValid() {
        return !used && !isExpired();
    }

    public void markAsUsed() {
        used = true;
        usedAt = new Timestamp(System.currentTimeMillis());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailToken)) return false;
        EmailToken that = (EmailToken) o;
        return id != null && id.equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
