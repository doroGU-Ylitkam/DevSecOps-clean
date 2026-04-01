package com.example.vulnerable.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

/**
 * ──────────────────────────────────────────────────────────────────
 * VULNERABILITY DEMO: Hardcoded Credentials + Sensitive Data Logging
 * ──────────────────────────────────────────────────────────────────
 *
 * Detected by:
 *   SonarQube – flags hardcoded passwords and credential logging
 *   OWASP ZAP – detects missing authentication on sensitive endpoints
 */
@RestController
@RequestMapping("/auth")
public class LoginController {

    private static final Logger log = LogManager.getLogger(LoginController.class);

    // ⚠️ VULNERABILITY 3: Hardcoded Credentials
    // Credentials are stored directly in source code.
    // Anyone with repo access can see them.
    // SonarQube rule: java:S2068 – Hard-coded credentials
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin123";
    private static final String DB_PASSWORD     = "superSecretDbPassword!";
    private static final String API_SECRET_KEY  = "sk-1234567890abcdef";

    /**
     * ⚠️ VULNERABILITY: Login endpoint with hardcoded credentials + logs password
     *
     * Attack example:
     *   POST /auth/login
     *   Body: {"username":"admin","password":"admin123"}
     *
     * Also vulnerable to brute force – no rate limiting or lockout.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // ⚠️ VULNERABILITY: Logs the plaintext password – sensitive data exposure
        // SonarQube rule: java:S2068, java:S3330
        log.info("Login attempt – username: " + username + ", password: " + password);

        if (ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password)) {
            log.info("Login successful for: " + username);
            return ResponseEntity.ok(Map.of(
                "status",  "success",
                "token",   API_SECRET_KEY,   // ⚠️ returns secret key in plain JSON
                "message", "Welcome, " + username
            ));
        }

        return ResponseEntity.status(401).body(Map.of("status", "failed"));
    }

    /**
     * ⚠️ VULNERABILITY: Exposes system configuration including credentials
     * No authentication required to access this endpoint.
     *
     * Attack example:
     *   GET /auth/config
     */
    @GetMapping("/config")
    public ResponseEntity<?> getConfig() {
        // ⚠️ VULNERABILITY: Returns sensitive internal configuration to anyone
        return ResponseEntity.ok(Map.of(
            "db_host",     "localhost:5432",
            "db_user",     "dbadmin",
            "db_password", DB_PASSWORD,       // ⚠️ hardcoded secret exposed via API
            "api_key",     API_SECRET_KEY,
            "environment", "production"
        ));
    }
}
