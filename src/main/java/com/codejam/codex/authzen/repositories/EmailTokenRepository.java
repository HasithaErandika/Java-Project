package com.codejam.codex.authzen.repositories;

import com.codejam.codex.authzen.models.EmailToken;
import com.codejam.codex.authzen.models.User;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface EmailTokenRepository extends JpaRepository<EmailToken, Long> {
    Optional<EmailToken> findByToken(@NotBlank String token);

    List<EmailToken> findByUserAndPurpose(User user, String purpose);

    @Modifying
    @Query("DELETE FROM EmailToken et WHERE et.expiresAt < CURRENT_TIMESTAMP")
    void deleteExpiredTokens();

    @Modifying
    @Query("DELETE FROM EmailToken et WHERE et.user = :user AND et.purpose = :purpose")
    void deleteByUserAndPurpose(@Param("user") User user, @Param("purpose") String purpose);

    @Query("SELECT et FROM EmailToken et WHERE et.user = :user AND et.purpose = :purpose AND et.expiresAt > CURRENT_TIMESTAMP")
    List<EmailToken> findValidTokensByUserAndPurpose(@Param("user") User user, @Param("purpose") String purpose);
}
