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
@Table(name = "permissions", uniqueConstraints = {
    @UniqueConstraint(columnNames = "name")
})
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Permission name is required")
    @Column(nullable = false, unique = true)
    private String name;

    @Column
    private String description;

    @OneToMany(mappedBy = "permission", fetch = FetchType.EAGER, cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<RolePermission> rolePermissions = new HashSet<>();
}
