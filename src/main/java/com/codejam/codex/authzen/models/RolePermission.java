package com.codejam.codex.authzen.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@ToString
@Table(name = "role_permissions", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"role_id", "permission_id"})
})
public class RolePermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull(message = "Role is required")
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false, updatable = false)
    @ToString.Exclude
    private Role role;

    @NotNull(message = "Permission is required")
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "permission_id", nullable = false, updatable = false)
    @ToString.Exclude
    private Permission permission;

    @PrePersist
    @PreUpdate
    private void validate() {
        if (role == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }
        if (permission == null) {
            throw new IllegalArgumentException("Permission cannot be null");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RolePermission)) return false;
        RolePermission that = (RolePermission) o;
        return role.getId().equals(that.getRole().getId()) &&
               permission.getId().equals(that.getPermission().getId());
    }

    @Override
    public int hashCode() {
        return 31 * role.getId().hashCode() + permission.getId().hashCode();
    }
}
