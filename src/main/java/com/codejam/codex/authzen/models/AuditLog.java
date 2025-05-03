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
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull(message = "User is required")
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "actor_id", nullable = false, updatable = false)
    @ToString.Exclude
    private User user;

    @NotBlank(message = "Action type is required")
    @Size(max = 50, message = "Action type cannot exceed 50 characters")
    @Pattern(regexp = "^[A-Z_]+$", message = "Action type must contain only uppercase letters and underscores")
    @Column(name = "action_type", nullable = false)
    private String actionType;

    @Size(max = 45, message = "IP address cannot exceed 45 characters")
    @Pattern(regexp = "^([0-9]{1,3}\\.){3}[0-9]{1,3}$", message = "Invalid IP address format")
    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "details", length = 1000)
    private String details;

    @NotNull(message = "Timestamp is required")
    @Column(nullable = false, updatable = false)
    private Timestamp timestamp;

    @PrePersist
    protected void onCreate() {
        timestamp = new Timestamp(System.currentTimeMillis());
        if (actionType != null) {
            actionType = actionType.trim().toUpperCase();
        }
        if (ipAddress != null) {
            ipAddress = ipAddress.trim();
        }
        if (details != null) {
            details = details.trim();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        if (actionType != null) {
            actionType = actionType.trim().toUpperCase();
        }
        if (ipAddress != null) {
            ipAddress = ipAddress.trim();
        }
        if (details != null) {
            details = details.trim();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuditLog)) return false;
        AuditLog auditLog = (AuditLog) o;
        return id != null && id.equals(auditLog.getId());
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
