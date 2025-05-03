package com.codejam.codex.authzen.configs;

import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import com.codejam.codex.authzen.repositories.UserRoleRepository;
import com.codejam.codex.authzen.utils.ValidationUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.List;
import java.util.regex.Pattern;

@Configuration
@RequiredArgsConstructor
public class RoleInitializer {

    private static final Logger logger = LoggerFactory.getLogger(RoleInitializer.class);
    private static final Pattern ROLE_NAME_PATTERN = Pattern.compile("^ROLE_[A-Z_]+$");

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ValidationUtil validationUtil;

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;

    @Bean
    CommandLineRunner initializeRolesAndAdmin() {
        return args -> {
            try {
                validateAdminCredentials();
                
                Role userRole = createRoleIfNotExists("ROLE_USER", "Default user role");
                Role adminRole = createRoleIfNotExists("ROLE_ADMIN", "Administrator with full access");

                createAdminUserIfNotExists(adminRole);
                
                logger.info("Role and admin initialization completed successfully");
            } catch (Exception e) {
                logger.error("Failed to initialize roles and admin: {}", e.getMessage(), e);
                throw e;
            }
        };
    }

    private void validateAdminCredentials() {
        if (!StringUtils.hasText(adminEmail)) {
            throw new IllegalStateException("Admin email is not configured");
        }
        if (!StringUtils.hasText(adminUsername)) {
            throw new IllegalStateException("Admin username is not configured");
        }
        if (!StringUtils.hasText(adminPassword)) {
            throw new IllegalStateException("Admin password is not configured");
        }
        validationUtil.validateEmail(adminEmail);
        validationUtil.validateUsername(adminUsername);
    }

    private Role createRoleIfNotExists(String name, String description) {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }
        if (!ROLE_NAME_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException("Invalid role name format. Must start with 'ROLE_' and contain only uppercase letters and underscores");
        }
        if (!StringUtils.hasText(description)) {
            throw new IllegalArgumentException("Role description cannot be empty");
        }

        List<Role> roles = roleRepository.findByName(name);

        if (roles.isEmpty()) {
            Role newRole = Role.builder()
                    .name(name)
                    .description(description)
                    .build();
            return roleRepository.save(newRole);
        }

        return roles.get(0);
    }

    private void createAdminUserIfNotExists(Role adminRole) {
        if (userRepository.findByEmail(adminEmail).isEmpty()) {
            User admin = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .isActive(true)
                    .isLocked(false)
                    .createdAt(new Timestamp(System.currentTimeMillis()))
                    .build();

            User savedAdmin = userRepository.save(admin);

            UserRole userRole = new UserRole();
            userRole.setUser(savedAdmin);
            userRole.setRole(adminRole);
            userRoleRepository.save(userRole);
            
            logger.info("Admin user created successfully: {}", adminUsername);
        } else {
            logger.info("Admin user already exists: {}", adminUsername);
        }
    }
}
