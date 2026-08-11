INSERT INTO users (username, password_hash, created_at) VALUES
('admin', '$2b$12$7u1w5sQf3z8QpP3wW9zUuO0w3m8N9fBv8CjQw3L4qQLdI8yNw5gW', '2026-08-06 05:00:00');

INSERT INTO attack_logs (ip_address, username, password, created_at, user_agent, operating_system, browser, failed_attempts) VALUES
('198.51.100.25', 'root', 'toor', '2026-08-06 05:12:00', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36', 'Windows', 'Chrome', 4),
('203.0.113.30', 'admin', 'password123', '2026-08-06 04:55:00', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/126.0 Safari/537.36', 'Linux', 'Firefox', 3),
('192.0.2.10', 'support', 'support2024', '2026-08-06 03:40:00', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.4', 'macOS', 'Safari', 2);
