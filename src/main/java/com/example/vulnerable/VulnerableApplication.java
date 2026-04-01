package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ⚠️  VULNERABLE APPLICATION – FOR THESIS DEMONSTRATION ONLY
 * DO NOT deploy to any real environment.
 */
@SpringBootApplication
public class VulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}
