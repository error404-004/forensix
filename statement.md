# FORENSIX — Project Statement

## 1. Problem Statement
Manual inspection of file modifications and system logs is error-prone, vulnerable to timestomping, and fails to provide defensible evidence during security incidents. Standard commercial File Integrity Monitoring (FIM) and Security Information and Event Management (SIEM) solutions are heavyweight, complex, and unfeasible for small labs or lightweight endpoint defense. FORENSIX solves this by providing a lightweight, autonomous desktop toolkit that establishes cryptographic SHA-256 baselines, detects file tampering and log anomalies, and records every security finding into a cryptographically sealed, tamper-evident hash-chained audit trail.

## 2. Scope of the Project
FORENSIX is designed as a standalone Java desktop application for local endpoint security monitoring, forensic triage, and DFIR (Digital Forensics & Incident Response) education:
- **In Scope:**
  - Local recursive directory baselining using streaming SHA-256 hashing.
  - Differential state scanning detecting ADDED, MODIFIED, DELETED, and UNCHANGED files.
  - Authentication and system log parsing with rule-based anomaly detection (brute-force bursts, off-hours access, blacklisted IPs, suspicious user probing).
  - Cryptographic tamper-evident hash-chained audit logging backed by application-level append-only SQLite storage.
  - One-click cryptographic verification of audit log integrity with broken-link pinpointing.
  - Human-readable forensic report generation and disk export.
  - Background scan scheduling via daemon executor service.
  - Responsive Swing graphical interface and comprehensive CLI mode.
- **Out of Scope:**
  - Live OS syslog socket daemon listening or distributed multi-agent networking.
  - Cloud server orchestration or remote alerting (SMS/Email).
  - Multi-user authentication or role-based access control (documented for future roadmap).

## 3. Target Users
- **Security Analysts & Blue Teamers:** Seeking an agile, zero-setup host integrity verification and forensic evidence collector for triage workstations or server endpoints.
- **System Administrators:** Needing an automated monitor to detect unauthorized configuration changes and web shell drops on critical server directories.
- **Cybersecurity / DFIR Students & Evaluators:** Exploring applied cryptographic integrity verification, hash-chained chain-of-custody logging, and secure Java engineering.

## 4. High-Level Features
1. **Cryptographic File Integrity Monitoring (FIM):**
   - Memory-bounded 8 KB chunked streaming SHA-256 hashing.
   - Comprehensive change detection (unauthorized modifications, file additions, stealth deletions).
2. **Resilient Log Anomaly Detection:**
   - Fault-tolerant log ingestion supporting pipe-delimited and auth log formats.
   - Sliding-window brute force detection ($\ge 5$ failed logins within 5 minutes).
   - Off-hours access detection (outside 08:00 - 19:00).
   - Threat intelligence blacklisted IP correlation and suspicious account probing.
3. **Tamper-Evident Hash-Chained Audit Trail:**
   - Application-level append-only SQLite DAO design (zero UPDATE or DELETE operations exposed).
   - Cryptographic linkage where $\text{record\_hash}_n = \text{SHA-256}(\text{canonical\_data}_n + "|" + \text{record\_hash}_{n-1})$.
   - One-click automated chain verification that immediately detects and reports external database tampering.
4. **Forensic Reporting & Analytics:**
   - Detailed plain text and Markdown report generation with cryptographic chain-of-custody summaries.
5. **Modern Swing Desktop Dashboard & CLI:**
   - Multi-tabbed interface with real-time metric cards, color-coded status badges, search filtering, and background multithreading (`SwingWorker`).
