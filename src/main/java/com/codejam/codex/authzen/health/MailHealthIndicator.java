package com.codejam.codex.authzen.health;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.MessagingException;
import java.util.Properties;

@Component
public class MailHealthIndicator implements HealthIndicator {

    private final JavaMailSender mailSender;

    public MailHealthIndicator(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public Health health() {
        try {
            if (mailSender instanceof JavaMailSenderImpl senderImpl) {
                Properties props = senderImpl.getJavaMailProperties();
                Session session = senderImpl.getSession();
                
                // Create a new transport for testing
                Transport transport = session.getTransport();
                try {
                    transport.connect(
                        props.getProperty("mail.smtp.host"),
                        senderImpl.getUsername(),
                        senderImpl.getPassword()
                    );
                    return Health.up()
                            .withDetail("service", "mail")
                            .withDetail("status", "UP")
                            .build();
                } finally {
                    if (transport != null) {
                        transport.close();
                    }
                }
            } else {
                return Health.down()
                        .withDetail("service", "mail")
                        .withDetail("status", "DOWN")
                        .withDetail("error", "Mail sender is not JavaMailSenderImpl")
                        .build();
            }
        } catch (MessagingException e) {
            return Health.down()
                    .withDetail("service", "mail")
                    .withDetail("status", "DOWN")
                    .withDetail("error", e.getMessage())
                    .build();
        } catch (Exception e) {
            return Health.down()
                    .withDetail("service", "mail")
                    .withDetail("status", "DOWN")
                    .withDetail("error", e.getMessage())
                    .build();
        }
    }
}