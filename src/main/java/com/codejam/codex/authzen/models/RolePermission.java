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
    @ManyToOne
    @JoinColumn(name = "role_id", nullable = false)
    @ToString.Exclude
    private Role role;

    @NotNull(message = "Permission is required")
    @ManyToOne
    @JoinColumn(name = "permission_id", nullable = false)
    @ToString.Exclude
    private Permission permission;
}
