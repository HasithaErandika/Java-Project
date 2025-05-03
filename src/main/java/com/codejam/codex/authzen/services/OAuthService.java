package com.codejam.codex.authzen.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class OAuthService {

    private static final Logger logger = LoggerFactory.getLogger(OAuthService.class);
    private static final Pattern CODE_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");
    private static final Pattern TOKEN_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    @Value("${github.client-id}")
    private String clientId;

    @Value("${github.client-secret}")
    private String clientSecret;

    @Value("${github.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate = new RestTemplate();

    private boolean isValidCode(String code) {
        return code != null && 
               !code.trim().isEmpty() && 
               CODE_PATTERN.matcher(code).matches();
    }

    private boolean isValidToken(String token) {
        return token != null && 
               !token.trim().isEmpty() && 
               TOKEN_PATTERN.matcher(token).matches();
    }

    public String getGithubAccessToken(String code) {
        if (!isValidCode(code)) {
            logger.error("Invalid authorization code");
            throw new IllegalArgumentException("Invalid authorization code");
        }

        try {
            String url = "https://github.com/login/oauth/access_token";

            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, String> body = Map.of(
                    "client_id", clientId,
                    "client_secret", clientSecret,
                    "code", code,
                    "redirect_uri", redirectUri
            );

            HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);
            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
                logger.error("Failed to get access token: Invalid response from GitHub");
                throw new RuntimeException("Failed to get access token: Invalid response from GitHub");
            }

            Object token = response.getBody().get("access_token");
            if (token == null) {
                logger.error("Failed to get access token: Token not found in response");
                throw new RuntimeException("Access token not found in response");
            }

            String accessToken = token.toString();
            if (!isValidToken(accessToken)) {
                logger.error("Failed to get access token: Invalid token format");
                throw new RuntimeException("Invalid access token format");
            }

            logger.info("Successfully obtained GitHub access token");
            return accessToken;
        } catch (HttpClientErrorException e) {
            logger.error("Failed to get access token: HTTP error - {}", e.getMessage());
            throw new RuntimeException("Failed to get access token: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error while getting access token", e);
            throw new RuntimeException("Unexpected error while getting access token", e);
        }
    }

    public Map<String, Object> getGithubUser(String accessToken) {
        if (!isValidToken(accessToken)) {
            logger.error("Invalid access token");
            throw new IllegalArgumentException("Invalid access token");
        }

        try {
            String url = "https://api.github.com/user";

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));

            HttpEntity<Void> request = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
                logger.error("Failed to get user info: Invalid response from GitHub");
                throw new RuntimeException("Failed to get user info: Invalid response from GitHub");
            }

            Map<String, Object> userInfo = response.getBody();
            if (!userInfo.containsKey("id") || !userInfo.containsKey("login") || !userInfo.containsKey("email")) {
                logger.error("Failed to get user info: Missing required fields");
                throw new RuntimeException("Failed to get user info: Missing required fields");
            }

            logger.info("Successfully obtained GitHub user info for user: {}", userInfo.get("login"));
            return userInfo;
        } catch (HttpClientErrorException e) {
            logger.error("Failed to get user info: HTTP error - {}", e.getMessage());
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error while getting user info", e);
            throw new RuntimeException("Unexpected error while getting user info", e);
        }
    }
}
