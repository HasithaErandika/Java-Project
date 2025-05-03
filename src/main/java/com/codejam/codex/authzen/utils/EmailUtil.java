package com.codejam.codex.authzen.utils;

import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Service
public class EmailUtil {

    private static final Logger logger = LoggerFactory.getLogger(EmailUtil.class);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
    private static final int MAX_EMAIL_LENGTH = 255;
    private static final int MAX_SUBJECT_LENGTH = 100;
    private static final int MAX_BODY_LENGTH = 10000;
    private static final int MAX_EMAILS_PER_HOUR = 5;
    private static final long RATE_LIMIT_WINDOW = TimeUnit.HOURS.toMillis(1);

    private final JavaMailSender javaMailSender;
    private final Map<String, EmailRateLimit> rateLimits = new ConcurrentHashMap<>();

    @Value("${email.from}")
    private String fromEmail;

    public EmailUtil(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    private static class EmailRateLimit {
        private int count;
        private long lastReset;

        public EmailRateLimit() {
            this.count = 0;
            this.lastReset = System.currentTimeMillis();
        }

        public boolean canSend() {
            long now = System.currentTimeMillis();
            if (now - lastReset >= RATE_LIMIT_WINDOW) {
                count = 0;
                lastReset = now;
            }
            return count < MAX_EMAILS_PER_HOUR;
        }

        public void increment() {
            count++;
        }
    }

    private boolean isValidEmail(String email) {
        return email != null && 
               email.length() <= MAX_EMAIL_LENGTH && 
               EMAIL_PATTERN.matcher(email).matches();
    }

    private boolean isValidSubject(String subject) {
        return subject != null && 
               !subject.trim().isEmpty() && 
               subject.length() <= MAX_SUBJECT_LENGTH;
    }

    private boolean isValidBody(String body) {
        return body != null && 
               !body.trim().isEmpty() && 
               body.length() <= MAX_BODY_LENGTH;
    }

    private boolean isValidResetLink(String resetLink) {
        return resetLink != null && 
               !resetLink.trim().isEmpty() && 
               resetLink.startsWith("http");
    }

    private boolean isRateLimited(String email) {
        EmailRateLimit limit = rateLimits.computeIfAbsent(email, k -> new EmailRateLimit());
        if (!limit.canSend()) {
            logger.warn("Rate limit exceeded for email: {}", email);
            return true;
        }
        limit.increment();
        return false;
    }

    private String validateAndFormatTemplate(String template, Map<String, String> placeholders) {
        if (template == null || template.trim().isEmpty()) {
            throw new IllegalArgumentException("Email template cannot be empty");
        }

        String formatted = template;
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            String placeholder = "${" + entry.getKey() + "}";
            if (!template.contains(placeholder)) {
                throw new IllegalArgumentException("Template missing required placeholder: " + placeholder);
            }
            formatted = formatted.replace(placeholder, entry.getValue());
        }

        if (formatted.contains("${")) {
            throw new IllegalArgumentException("Template contains unprocessed placeholders");
        }

        return formatted;
    }

    /**
     * Sends a plain text email (e.g., password reset email).
     *
     * @param toEmail   The recipient email.
     * @param subject   The email subject.
     * @param body      The email body (can include placeholders like ${RESET_LINK}).
     * @param resetLink The reset link to be injected into body.
     * @return true if email is sent successfully, false otherwise.
     */
    public boolean sendPasswordResetEmail(String toEmail, String subject, String body, String resetLink) {
        if (!isValidEmail(toEmail) || !isValidSubject(subject) || 
            !isValidBody(body) || !isValidResetLink(resetLink)) {
            logger.error("Invalid email parameters: toEmail={}, subject={}, body={}, resetLink={}", 
                        toEmail, subject, body, resetLink);
            return false;
        }

        if (isRateLimited(toEmail)) {
            return false;
        }

        try {
            String formattedBody = validateAndFormatTemplate(body, Map.of("RESET_LINK", resetLink));
            
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject(subject);
            message.setText(formattedBody);
            
            javaMailSender.send(message);
            logger.info("Password reset email sent successfully to {}", toEmail);
            return true;
        } catch (MailException e) {
            logger.error("Failed to send password reset email to {}: {}", toEmail, e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid email template: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Sends an HTML email (can be used for richer formatted emails).
     *
     * @param toEmail   The recipient email.
     * @param subject   The email subject.
     * @param body      The HTML body (can include placeholders like ${RESET_LINK}).
     * @param resetLink The reset link to be injected into body.
     * @return true if email is sent successfully, false otherwise.
     */
    public boolean sendPasswordResetEmailHtml(String toEmail, String subject, String body, String resetLink) {
        if (!isValidEmail(toEmail) || !isValidSubject(subject) || 
            !isValidBody(body) || !isValidResetLink(resetLink)) {
            logger.error("Invalid email parameters: toEmail={}, subject={}, body={}, resetLink={}", 
                        toEmail, subject, body, resetLink);
            return false;
        }

        if (isRateLimited(toEmail)) {
            return false;
        }

        try {
            String formattedBody = validateAndFormatTemplate(body, Map.of("RESET_LINK", resetLink));
            
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(formattedBody, true);
            
            javaMailSender.send(mimeMessage);
            logger.info("HTML password reset email sent successfully to {}", toEmail);
            return true;
        } catch (MailException | jakarta.mail.MessagingException e) {
            logger.error("Failed to send HTML password reset email to {}: {}", toEmail, e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid email template: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Sends a verification email.
     *
     * @param toEmail   The recipient email.
     * @param subject   The email subject.
     * @param body      The email body (can include placeholders like ${VERIFICATION_LINK}).
     * @param verificationLink The verification link to be injected into body.
     * @return true if email is sent successfully, false otherwise.
     */
    public boolean sendVerificationEmail(String toEmail, String subject, String body, String verificationLink) {
        if (!isValidEmail(toEmail) || !isValidSubject(subject) || 
            !isValidBody(body) || !isValidResetLink(verificationLink)) {
            logger.error("Invalid email parameters: toEmail={}, subject={}, body={}, verificationLink={}", 
                        toEmail, subject, body, verificationLink);
            return false;
        }

        if (isRateLimited(toEmail)) {
            return false;
        }

        try {
            String formattedBody = validateAndFormatTemplate(body, Map.of("VERIFICATION_LINK", verificationLink));
            
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(formattedBody, true);
            
            javaMailSender.send(mimeMessage);
            logger.info("Verification email sent successfully to {}", toEmail);
            return true;
        } catch (MailException | jakarta.mail.MessagingException e) {
            logger.error("Failed to send verification email to {}: {}", toEmail, e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid email template: {}", e.getMessage());
            return false;
        }
    }
}
