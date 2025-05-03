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
import java.util.concurrent.TimeUnit;

@Component
public class MailHealthIndicator implements HealthIndicator {

    private static final int CONNECTION_TIMEOUT_MS = 5000;
    private final JavaMailSender mailSender;

    public MailHealthIndicator(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public Health health() {
        if (!(mailSender instanceof JavaMailSenderImpl senderImpl)) {
            return Health.down()
                    .withDetail("service", "mail")
                    .withDetail("status", "DOWN")
                    .withDetail("error", "Mail sender is not JavaMailSenderImpl")
                    .build();
        }

        Properties props = senderImpl.getJavaMailProperties();
        Session session = senderImpl.getSession();
        
        // Set connection timeout
        props.setProperty("mail.smtp.connectiontimeout", String.valueOf(CONNECTION_TIMEOUT_MS));
        props.setProperty("mail.smtp.timeout", String.valueOf(CONNECTION_TIMEOUT_MS));
        
        Transport transport = null;
        try {
            transport = session.getTransport();
            transport.connect(
                props.getProperty("mail.smtp.host"),
                senderImpl.getUsername(),
                senderImpl.getPassword()
            );
            
            return Health.up()
                    .withDetail("service", "mail")
                    .withDetail("status", "UP")
                    .withDetail("host", props.getProperty("mail.smtp.host"))
                    .withDetail("port", props.getProperty("mail.smtp.port"))
                    .build();
        } catch (MessagingException e) {
            return Health.down()
                    .withDetail("service", "mail")
                    .withDetail("status", "DOWN")
                    .withDetail("error", e.getMessage())
                    .withDetail("host", props.getProperty("mail.smtp.host"))
                    .withDetail("port", props.getProperty("mail.smtp.port"))
                    .build();
        } catch (Exception e) {
            return Health.down()
                    .withDetail("service", "mail")
                    .withDetail("status", "DOWN")
                    .withDetail("error", e.getMessage())
                    .build();
        } finally {
            if (transport != null) {
                try {
                    transport.close();
                } catch (MessagingException e) {
                    // Log the error but don't affect the health status
                }
            }
        }
    }
}