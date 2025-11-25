-- Vulnerability Scanner Database Schema

-- API Keys table for authentication
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    user_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Scan Jobs table - tracks all vulnerability scans
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type VARCHAR(50) NOT NULL, -- 'docker-image' or 'web-url'
    target VARCHAR(500) NOT NULL,
    status VARCHAR(50) DEFAULT 'queued', -- queued, scanning, completed, failed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    api_key_id UUID REFERENCES api_keys(id),
    error_message TEXT
);

-- Vulnerabilities table - stores detected CVEs
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
    cve_id VARCHAR(50),
    severity VARCHAR(20), -- CRITICAL, HIGH, MEDIUM, LOW
    package_name VARCHAR(255),
    installed_version VARCHAR(100),
    fixed_version VARCHAR(100),
    title TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_created_at ON scan_jobs(created_at);
CREATE INDEX idx_vulnerabilities_scan_job ON vulnerabilities(scan_job_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);

-- Sample data
INSERT INTO api_keys (key_hash, user_email) 
VALUES ('sk_test_12345_hashed', 'demo@example.com');
