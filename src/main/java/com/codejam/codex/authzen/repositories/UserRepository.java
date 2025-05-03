package com.codejam.codex.authzen.repositories;

import com.codejam.codex.authzen.models.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    Optional<User> findByUsernameOrEmail(String username, String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Query("SELECT DISTINCT p.name FROM User u " +
            "JOIN u.userRoles ur " +
            "JOIN ur.role r " +
            "JOIN r.rolePermissions rp " +
            "JOIN rp.permission p " +
            "WHERE u.username = :username")
    List<String> findPermissionNamesByUsername(@Param("username") String username);

    @EntityGraph(attributePaths = {"userRoles", "userRoles.role", "userRoles.role.rolePermissions", "userRoles.role.rolePermissions.permission"})
    Optional<User> findWithRolesAndPermissionsByUsername(String username);

    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.locked = false WHERE u.username = :username")
    void resetFailedLoginAttempts(@Param("username") String username);

    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.username = :username")
    void incrementFailedLoginAttempts(@Param("username") String username);

    @Modifying
    @Query("UPDATE User u SET u.locked = true WHERE u.username = :username")
    void lockUser(@Param("username") String username);

    @Query("SELECT u FROM User u WHERE u.lastLoginAt < :date AND u.active = true")
    List<User> findInactiveUsers(@Param("date") java.sql.Timestamp date);

    @Query("SELECT u FROM User u WHERE u.passwordChangedAt < :date")
    List<User> findUsersWithExpiredPasswords(@Param("date") java.sql.Timestamp date);
}
