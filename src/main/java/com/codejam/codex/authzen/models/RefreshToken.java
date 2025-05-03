package com.codejam.codex.authzen.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.sql.Timestamp;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@ToString
@Table(name = "refresh_tokens", uniqueConstraints = {
    @UniqueConstraint(columnNames = "token")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Token is required")
    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @NotNull(message = "Expiration time is required")
    @Column(name = "expires_at", nullable = false)
    private Timestamp expiresAt;

    @NotNull(message = "User is required")
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    @ToString.Exclude
    private User user;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Timestamp createdAt;

    @Column(name = "last_used_at")
    private Timestamp lastUsedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = new Timestamp(System.currentTimeMillis());
        if (expiresAt == null) {
            throw new IllegalArgumentException("Expiration time is required");
        }
    }

    @PreUpdate
    protected void onUpdate() {
        if (token != null) {
            token = token.trim();
        }
    }

    public boolean isExpired() {
        return expiresAt.before(new Timestamp(System.currentTimeMillis()));
    }

    public boolean isValid() {
        return !revoked && !isExpired();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken)) return false;
        RefreshToken that = (RefreshToken) o;
        return id != null && id.equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
