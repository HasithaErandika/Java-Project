package com.codejam.codex.authzen.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;

import java.util.List;
import java.util.Map;

@Service
public class OAuthService {

    @Value("${github.client-id}")
    private String clientId;

    @Value("${github.client-secret}")
    private String clientSecret;

    @Value("${github.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate = new RestTemplate();

    public String getGithubAccessToken(String code) {
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
                throw new RuntimeException("Failed to get access token");
            }

            Object token = response.getBody().get("access_token");
            if (token == null) {
                throw new RuntimeException("Access token not found in response");
            }

            return token.toString();
        } catch (HttpClientErrorException e) {
            throw new RuntimeException("Failed to get access token: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error while getting access token", e);
        }
    }

    public Map<String, Object> getGithubUser(String accessToken) {
        try {
            String url = "https://api.github.com/user";

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));

            HttpEntity<Void> request = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
            if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null) {
                throw new RuntimeException("Failed to get user info");
            }

            return response.getBody();
        } catch (HttpClientErrorException e) {
            throw new RuntimeException("Failed to get user info: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error while getting user info", e);
        }
    }
}
