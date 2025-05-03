package com.codejam.codex.authzen.dtos.outputs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for registration response containing user details and verification status.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {
    private Long id;
    private String username;
    private String email;
    private boolean emailVerified;
    private List<String> roles;
    private String verificationToken;
    private String message;
} 