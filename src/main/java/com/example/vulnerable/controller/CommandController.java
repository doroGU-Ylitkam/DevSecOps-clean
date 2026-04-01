package com.example.vulnerable.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ──────────────────────────────────────────────────────────────────
 * VULNERABILITY DEMO: OS Command Injection
 * ──────────────────────────────────────────────────────────────────
 *
 * Detected by:
 *   SonarQube – flags Runtime.exec() with user input (java:S4721)
 *   OWASP ZAP – active scan detects command injection responses
 */
@RestController
@RequestMapping("/system")
public class CommandController {

    private static final Logger log = LogManager.getLogger(CommandController.class);

    /**
     * ⚠️ VULNERABILITY 4: OS Command Injection
     *
     * The 'host' parameter is passed directly to Runtime.exec()
     * without sanitization, allowing arbitrary command execution.
     *
     * Normal usage:
     *   GET /system/ping?host=localhost
     *   GET /system/ping?host=google.com
     *
     * Attack examples:
     *   GET /system/ping?host=localhost; cat /etc/passwd
     *   GET /system/ping?host=localhost && whoami
     *   GET /system/ping?host=localhost | ls -la /
     *
     * SonarQube rule: java:S4721 – OS commands should not be vulnerable to injection
     */
    @GetMapping("/ping")
    public ResponseEntity<?> ping(@RequestParam String host) {

        // ⚠️ VULNERABILITY: User input logged via vulnerable Log4j
        log.info("Pinging host: " + host);

        try {
            // ⚠️ VULNERABILITY: Direct command injection – host is not sanitized
            // Safe alternative: use InetAddress.getByName(host).isReachable(timeout)
            String[] command = {"/bin/sh", "-c", "ping -c 1 " + host};
            Process process = Runtime.getRuntime().exec(command);

            String output = new BufferedReader(
                new InputStreamReader(process.getInputStream()))
                .lines()
                .collect(Collectors.joining("\n"));

            String errors = new BufferedReader(
                new InputStreamReader(process.getErrorStream()))
                .lines()
                .collect(Collectors.joining("\n"));

            return ResponseEntity.ok(Map.of(
                "host",   host,
                "output", output,
                "errors", errors
            ));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                Map.of("error", e.getMessage())
            );
        }
    }

    /**
     * ⚠️ VULNERABILITY 5: Path Traversal + Information Disclosure
     *
     * Reads arbitrary files from the filesystem based on user input.
     *
     * Attack examples:
     *   GET /system/readfile?path=app.log
     *   GET /system/readfile?path=../../etc/passwd
     *   GET /system/readfile?path=../../etc/shadow
     *
     * Detected by: SonarQube (java:S2083), OWASP ZAP
     */
    @GetMapping("/readfile")
    public ResponseEntity<?> readFile(@RequestParam String path) {

        log.info("Reading file: " + path);

        try {
            // ⚠️ VULNERABILITY: No path sanitization – allows directory traversal
            String[] command = {"/bin/sh", "-c", "cat " + path};
            Process process = Runtime.getRuntime().exec(command);

            String content = new BufferedReader(
                new InputStreamReader(process.getInputStream()))
                .lines()
                .collect(Collectors.joining("\n"));

            return ResponseEntity.ok(Map.of("path", path, "content", content));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }
}
