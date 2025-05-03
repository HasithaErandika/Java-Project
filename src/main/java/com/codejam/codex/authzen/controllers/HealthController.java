package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.responses.HealthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(HealthController.class);

    @Autowired
    private DataSource dataSource;

    @Autowired
    private HealthIndicator mailHealthIndicator;

    @GetMapping
    public ResponseEntity<HealthResponse> checkHealth() {
        Map<String, String> services = new HashMap<>();
        String overallStatus = "UP";
        
        // Check database health
        try (Connection connection = dataSource.getConnection()) {
            services.put("database", "UP");
        } catch (SQLException e) {
            logger.error("Database health check failed: {}", e.getMessage());
            services.put("database", "DOWN");
            overallStatus = "DOWN";
        }

        // Check mail service health
        try {
            Health mailHealth = mailHealthIndicator.health();
            services.put("mail", mailHealth.getStatus().getCode());
            if (!mailHealth.getStatus().equals(Health.up().build().getStatus())) {
                overallStatus = "DOWN";
            }
        } catch (Exception e) {
            logger.error("Mail service health check failed: {}", e.getMessage());
            services.put("mail", "DOWN");
            overallStatus = "DOWN";
        }

        // Check GitHub OAuth health
        try {
            // Add actual GitHub OAuth health check here
            services.put("github_oauth", "UP");
        } catch (Exception e) {
            logger.error("GitHub OAuth health check failed: {}", e.getMessage());
            services.put("github_oauth", "DOWN");
            overallStatus = "DOWN";
        }

        HealthResponse response = new HealthResponse(
                overallStatus,
                services,
                System.currentTimeMillis()
        );

        return ResponseEntity.ok(response);
    }
}
