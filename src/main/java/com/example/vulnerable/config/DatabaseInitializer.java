package com.example.vulnerable.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Initialises the in-memory H2 database with sample tables and data
 * for demonstrating SQL injection and IDOR vulnerabilities.
 */
@Component
public class DatabaseInitializer implements CommandLineRunner {

    private static final Logger log = LogManager.getLogger(DatabaseInitializer.class);

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) {
        log.info("Initialising vulnerable demo database...");

        // Create users table
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50),
                password VARCHAR(100),
                email    VARCHAR(100),
                role     VARCHAR(20),
                is_admin BOOLEAN DEFAULT FALSE
            )
        """);

        // ⚠️ Sample data with plaintext passwords (intentionally insecure)
        jdbcTemplate.execute("""
            INSERT INTO users (username, password, email, role, is_admin) VALUES
                ('admin',   'admin123',      'admin@example.com',   'ADMIN', TRUE),
                ('alice',   'password1',     'alice@example.com',   'USER',  FALSE),
                ('bob',     'bob_secret_99', 'bob@example.com',     'USER',  FALSE),
                ('charlie', 'ch@rlie2024',   'charlie@example.com', 'USER',  FALSE)
        """);

        // Create products table (for XSS/search demo)
        jdbcTemplate.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id    INTEGER PRIMARY KEY AUTO_INCREMENT,
                name  VARCHAR(100),
                price DECIMAL(10,2)
            )
        """);

        jdbcTemplate.execute("""
            INSERT INTO products (name, price) VALUES
                ('Laptop',     999.99),
                ('Mouse',       29.99),
                ('Keyboard',    79.99)
        """);

        log.info("Database initialised with sample data.");
    }
}
