package com.codejam.codex.authzen.health;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import javax.mail.Transport;

@Component
public class MailHealthIndicator implements HealthIndicator {

    private final JavaMailSender mailSender;

    public MailHealthIndicator(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public Health health() {
        try {
            // Cast to JavaMailSenderImpl to access properties
            if (mailSender instanceof JavaMailSenderImpl senderImpl) {
                // Get mail session and properties
                var session = senderImpl.getSession();
                var props = session.getProperties();

                // Attempt to connect to the mail server
                try (Transport transport = session.getTransport()) {
                    transport.connect(
                            props.getProperty("mail.smtp.host"),
                            senderImpl.getUsername(),
                            senderImpl.getPassword()
                    );
                    return Health.up()
                            .withDetail("service", "mail")
                            .withDetail("status", "UP")
                            .build();
                } catch (MessagingException e) {
                    return Health.down()
                            .withDetail("service", "mail")
                            .withDetail("status", "DOWN")
                            .withDetail("error", e.getMessage())
                            .build();
                }
            } else {
                return Health.down()
                        .withDetail("service", "mail")
                        .withDetail("status", "DOWN")
                        .withDetail("error", "Mail sender is not JavaMailSenderImpl")
                        .build();
            }
        } catch (Exception e) {
            return Health.down()
                    .withDetail("service", "mail")
                    .withDetail("status", "DOWN")
                    .withDetail("error", e.getMessage())
                    .build();
        }
    }
}