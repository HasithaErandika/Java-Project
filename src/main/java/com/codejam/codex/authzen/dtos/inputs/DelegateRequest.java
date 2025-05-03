package com.codejam.codex.authzen.dtos.inputs;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DelegateRequest {
    @NotNull
    private String targetUsername;

    @NotNull
    private List<String> permissions;

    private String reason;
}
