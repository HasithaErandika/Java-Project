package com.codejam.codex.authzen.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@ToString
@Table(name = "roles", uniqueConstraints = {
    @UniqueConstraint(columnNames = "name")
})
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Role name is required")
    @Column(nullable = false, unique = true)
    private String name;

    @Column
    private String description;

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL)
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();

    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL)
    @Builder.Default
    private Set<RolePermission> rolePermissions = new HashSet<>();
}