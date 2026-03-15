package com.example.app;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class HealthController {

    @GetMapping("/")
    public Map<String, String> index() {
        return Map.of(
            "status",  "running",
            "service", "spring-boot-app",
            "version", "1.0"
        );
    }

    @GetMapping("/api/hello")
    public Map<String, String> hello() {
        return Map.of("message", "Hello from DevSecOps prototype!");
    }
}
