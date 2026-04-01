package com.example.vulnerable.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Map;

/**
 * ──────────────────────────────────────────────────────────────────
 * VULNERABILITY DEMO: Insecure Direct Object Reference (IDOR)
 *                     + Missing Authentication
 *                     + Mass Assignment
 * ──────────────────────────────────────────────────────────────────
 *
 * Detected by:
 *   SonarQube – missing access control annotations
 *   OWASP ZAP – unauthenticated access to sensitive endpoints
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private static final Logger log = LogManager.getLogger(UserController.class);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * ⚠️ VULNERABILITY 6: Insecure Direct Object Reference (IDOR)
     *                     + No Authentication
     *
     * Any user can access any other user's data by simply changing the ID.
     * No session check, no authorization check.
     *
     * Attack examples:
     *   GET /users/1   → admin user data
     *   GET /users/2   → other user's private data
     *   GET /users/999
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable int id) {

        // ⚠️ VULNERABILITY: No authentication or authorization check
        // Anyone can call this endpoint
        log.info("Fetching user with id: " + id);

        try {
            // ⚠️ VULNERABILITY: SQL injection via path variable (int here,
            // but same pattern is dangerous with String parameters)
            List<Map<String, Object>> user = jdbcTemplate.queryForList(
                "SELECT * FROM users WHERE id = " + id
            );

            if (user.isEmpty()) {
                return ResponseEntity.status(404).body(Map.of("error", "User not found"));
            }
            // ⚠️ VULNERABILITY: Returns all fields including password hash
            return ResponseEntity.ok(user.get(0));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * ⚠️ VULNERABILITY 7: No authentication on admin endpoint
     *
     * Returns all users including passwords. No access control.
     *
     * Attack example:
     *   GET /users/all
     */
    @GetMapping("/all")
    public ResponseEntity<?> getAllUsers() {
        // ⚠️ VULNERABILITY: Admin-level data exposed without any authentication
        log.warn("All users fetched – no auth check performed");
        List<Map<String, Object>> users = jdbcTemplate.queryForList("SELECT * FROM users");
        return ResponseEntity.ok(users);
    }

    /**
     * ⚠️ VULNERABILITY 8: Mass Assignment
     *
     * Accepts any fields in the request body and writes them directly
     * to the database, including privileged fields like 'role' or 'isAdmin'.
     *
     * Attack example:
     *   POST /users/register
     *   Body: {"username":"hacker","password":"pass","role":"ADMIN","isAdmin":true}
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, Object> userData) {

        String username = (String) userData.get("username");
        String password = (String) userData.get("password");

        // ⚠️ VULNERABILITY: Logs plaintext password
        log.info("Registering user: " + username + " with password: " + password);

        // ⚠️ VULNERABILITY: Mass assignment – role and isAdmin come from user input
        String role    = (String)  userData.getOrDefault("role", "USER");
        boolean isAdmin = (boolean) userData.getOrDefault("isAdmin", false);

        // ⚠️ VULNERABILITY: Password stored in plaintext (no hashing)
        // ⚠️ VULNERABILITY: SQL injection via string concatenation
        String sql = "INSERT INTO users (username, password, role, is_admin) VALUES ('"
            + username + "','" + password + "','" + role + "'," + isAdmin + ")";

        jdbcTemplate.execute(sql);

        return ResponseEntity.ok(Map.of(
            "message", "User registered",
            "username", username,
            "role", role,
            "isAdmin", isAdmin
        ));
    }
}
