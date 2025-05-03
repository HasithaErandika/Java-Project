package com.codejam.codex.authzen.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;

import java.sql.Timestamp;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@ToString
@Table(name = "oauth_providers", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"provider", "external_user_id"})
})
public class OauthProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull(message = "User is required")
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    @ToString.Exclude
    private User user;

    @NotBlank(message = "Provider is required")
    @Pattern(regexp = "^(GITHUB|GOOGLE|FACEBOOK)$", message = "Provider must be GITHUB, GOOGLE, or FACEBOOK")
    @Column(nullable = false)
    private String provider;

    @NotBlank(message = "External user ID is required")
    @Column(name = "external_user_id", nullable = false)
    private String externalUserId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Timestamp createdAt;

    @Column(name = "last_used_at")
    private Timestamp lastUsedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = new Timestamp(System.currentTimeMillis());
        if (provider != null) {
            provider = provider.toUpperCase();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        if (provider != null) {
            provider = provider.toUpperCase();
        }
        if (externalUserId != null) {
            externalUserId = externalUserId.trim();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OauthProvider)) return false;
        OauthProvider that = (OauthProvider) o;
        return id != null && id.equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
