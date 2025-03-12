-- Schema for storing network pentest data

-- Table for storing vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER,
    service TEXT,
    type TEXT NOT NULL,
    cve_id TEXT,
    cvss_score REAL,
    severity TEXT NOT NULL,
    description TEXT,
    metadata TEXT,  -- JSON field for additional data
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index on host and severity for quick lookups
CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulnerabilities(host);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(type);

-- Table for storing nmap scan results
CREATE TABLE IF NOT EXISTS nmap_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    script_id TEXT,
    script_output TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index on host and port for quick lookups
CREATE INDEX IF NOT EXISTS idx_nmap_host ON nmap_scans(host);
CREATE INDEX IF NOT EXISTS idx_nmap_port ON nmap_scans(port); 