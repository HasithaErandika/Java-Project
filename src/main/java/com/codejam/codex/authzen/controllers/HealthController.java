package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.responses.HealthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/authenticate/health")
public class HealthController {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private HealthIndicator mailHealthIndicator;

    @GetMapping
    public ResponseEntity<HealthResponse> checkHealth() {
        Map<String, String> services = new HashMap<>();
        
        // Check database health
        try (Connection connection = dataSource.getConnection()) {
            services.put("database", "UP");
        } catch (SQLException e) {
            services.put("database", "DOWN");
        }

        // Check mail service health
        Health mailHealth = mailHealthIndicator.health();
        services.put("mail", mailHealth.getStatus().getCode());

        // Check GitHub OAuth health (you would need to implement this)
        services.put("github_oauth", "UP");

        HealthResponse response = new HealthResponse(
                "UP",
                services,
                System.currentTimeMillis()
        );

        return ResponseEntity.ok(response);
    }
}
