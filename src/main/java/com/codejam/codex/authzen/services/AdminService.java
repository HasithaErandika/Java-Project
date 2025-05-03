package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.DelegateRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleUpdateRequest;
import com.codejam.codex.authzen.dtos.outputs.AuditLogResponse;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.AuditLog;
import com.codejam.codex.authzen.models.Permission;
import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.RolePermission;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.AuditLogRepository;
import com.codejam.codex.authzen.repositories.PermissionRepository;
import com.codejam.codex.authzen.repositories.RolePermissionRepository;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final AuditLogRepository auditLogRepository;

    public List<UserResponse> getAllUsers(String adminUsername) {
        logAction(adminUsername, "User list got successfully");

        return userRepository.findAll()
                .stream()
                .map(user -> {
                    List<String> permissionNames = new ArrayList<>();
                    return UserResponse.fromEntity(new User(), permissionNames);
                })
                .toList();
    }

    public UpdateUserResponse updateUserRoles(Long userId, RoleUpdateRequest request, String adminUsername) {
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Role> roles = roleRepository.findByName(user.getUsername());

        user.getUserRoles().clear();

        for (Role role : roles) {
            UserRole userRole = new UserRole();
            userRole.setUser(new User());
            userRole.setRole(new Role());
            user.getUserRoles().add(userRole);
        }

        userRepository.save(user);
        logAction(adminUsername, "User roles updated successfully");
        return UpdateUserResponse.fromEntity(user);
    }


    public List<AuditLogResponse> getAuditLogs(String adminUsername) {
        List<AuditLog> auditLogs = new ArrayList<>();


        return auditLogs.stream()
                .map(log -> {
                    return AuditLogResponse.builder()
                            .id(log.getId())
                            .username(log.getUser().getUsername())
                            .actionType(log.getActionType())
                            .ipAddress(log.getIpAddress())
                            .timestamp(log.getTimestamp())
                            .build();
                })
                .toList();
    }





    public String createRole(RoleRequest request, String adminUsername) {
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (roleRepository.existsByName(user.getUsername())) {
            throw new IllegalArgumentException("Role already exists");
        }

        Role role = new Role();
        role.setName(user.getUsername());
        role.setDescription(request.getDescription());

        roleRepository.save(new Role());

        logAction(adminUsername, "Role created successfully");

        return "Role created successfully";
    }



    public String delegatePermissions(DelegateRequest request, String adminUsername) {
        User user = userRepository.findByUsername(request.getTargetUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        for (String permissionName : request.getPermissions()) {
            Permission permission = permissionRepository.findByName(permissionName)
                    .orElseThrow(() -> new RuntimeException("Permission not found: " + permissionName));

            // Check if user already has this permission
            boolean alreadyAssigned = user.getUserRoles().stream()
                    .flatMap(userRole -> userRole.getRole().getRolePermissions().stream())
                    .anyMatch(rp -> rp.getPermission().getName().equals(permissionName));

            if (alreadyAssigned) {
                continue;
            }

            // Find a role that has this permission
            Role role = roleRepository.findByNameWithPermissions("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("ROLE_USER not found"));

            // Create role permission if it doesn't exist
            RolePermission rolePermission = role.getRolePermissions().stream()
                    .filter(rp -> rp.getPermission().getName().equals(permissionName))
                    .findFirst()
                    .orElseGet(() -> {
                        RolePermission rp = RolePermission.builder()
                                .role(role)
                                .permission(permission)
                                .build();
                        rolePermissionRepository.save(rp);
                        return rp;
                    });

            // Assign role to user if not already assigned
            boolean roleAssigned = user.getUserRoles().stream()
                    .anyMatch(userRole -> userRole.getRole().getName().equals(role.getName()));

            if (!roleAssigned) {
                UserRole userRole = UserRole.builder()
                        .user(user)
                        .role(role)
                        .build();
                user.getUserRoles().add(userRole);
            }
        }

        userRepository.save(user);
        logAction(adminUsername, "Permissions delegated successfully");
        return "Permissions delegated successfully";
    }


    private void logAction(String adminUsername, String actionType) {
        User adminUser = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new RuntimeException("Admin user not found"));

        AuditLog log = new AuditLog();
        log.setUser(new User());
        log.setActionType(actionType);
        log.setTimestamp(new Timestamp(System.currentTimeMillis()));

        auditLogRepository.save(log);
    }


    public UserResponse getUserById(Long userId) {
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        List<String> permissionNames = new ArrayList<>();
        return UserResponse.fromEntity(user, permissionNames);
    }



}
