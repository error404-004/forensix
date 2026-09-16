# FORENSIX — File Integrity Monitoring & Security Audit Toolkit

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#testing)
[![Java Version](https://img.shields.io/badge/Java-17%2B-blue.svg)](#tech-stack)
[![Security Standard](https://img.shields.io/badge/Cryptography-SHA--256-blueviolet.svg)](#tamper-evident-audit-trail)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> A lightweight, autonomous desktop File Integrity Monitor (FIM) and DFIR security audit toolkit in Java 17, featuring streaming SHA-256 baseline hashing, rule-based log anomaly detection, and a cryptographically sealed, tamper-evident hash-chained audit trail.

---

## 1. Project Overview & Problem Statement

Unauthorized file alterations (such as web shells deposited on web servers, compromised system binaries, or configuration tampering) represent early indicators of compromise (IoCs) in enterprise breaches. Traditional manual integrity checking relying on filesystem timestamps is vulnerable to **timestomping** attacks and leaves no defensible audit trail. Commercial FIM solutions (Tripwire, OSSEC) are heavyweight and require dedicated client-server infrastructure.

**FORENSIX** provides an agile, zero-external-dependency desktop tool tailored for cybersecurity analysts, blue teamers, and incident responders. It establishes cryptographic (SHA-256) baselines for local file hierarchies, performs rapid differential scans to classify added/modified/deleted files, cross-references system and authentication logs to flag suspicious security patterns, and records every finding into an **application-level append-only, tamper-evident hash chain** stored in SQLite.

---

## 2. Key Features

### 🔍 Module 1: File Integrity Monitoring (FIM)
- **Streaming SHA-256 Hashing:** Employs memory-bounded 8 KB streaming buffers (`java.security.MessageDigest`), capable of hashing multi-gigabyte files without heap exhaustion.
- **Differential State Scanning:** Recursively traverses directory structures (`java.nio.file.Files.walk`) and diffs current disk state against stored baselines:
  - `ADDED`: Newly created files absent from baseline.
  - `MODIFIED`: Altered files with divergent SHA-256 checksums.
  - `DELETED`: Previously baselined files deleted from disk.
  - `UNCHANGED`: Clean, verified files.
  - `SCAN_ERROR`: Permission-denied or locked files recorded without scan termination.
- **Security Hardening:** Strictly prevents directory traversal outside the monitored root and ignores external symbolic links.

### 📜 Module 2: Log Analysis & Anomaly Detection
- **Resilient Parsing:** Ingests authentication/system log files line-by-line using bounded token parsing to prevent Regular Expression Denial of Service (ReDoS). Malformed lines are gracefully skipped and accounted for in metrics.
- **Rule-Based Threat Detection:**
  - **Rule 1 (Brute-Force Attack):** Flags $\ge 5$ failed login attempts from the same IP address within a 5-minute sliding window (`HIGH` severity).
  - **Rule 2 (Off-Hours Activity):** Flags authentications outside configured working hours (e.g., 08:00 - 19:00) (`MEDIUM` severity).
  - **Rule 3 (Threat Intelligence Blacklist):** Flags connections from known malicious IP addresses (`CRITICAL` severity).
  - **Rule 4 (Suspicious Account Probing):** Flags failed attempts targeting high-privilege usernames like `root`, `admin`, `oracle`, or `postgres` (`HIGH` severity).

### 🔗 Module 3: Tamper-Evident Hash-Chained Audit Trail
- **Application-Level Append-Only Design:** The DAO layer (`AuditLogDAO`) strictly exposes insertion and ordered retrieval methods. No `UPDATE`, `DELETE`, or table truncate methods exist.
- **Cryptographic Hash Chaining:** Every audit record cryptographically binds its canonical representation to the hash of the preceding record:
  $$\text{canonical\_data}_n = \text{recordType} + "|" + \text{recordRefId} + "|" + \text{payload} + "|" + \text{createdAt}$$
  $$\text{record\_hash}_n = \text{SHA-256}(\text{canonical\_data}_n + "|" + \text{record\_hash}_{n-1})$$
  *(Genesis record links to 64 zeros).*
- **Tamper Evidence Verification:** Traverses the chain from genesis to the latest record in deterministic order, recomputing hashes and validating backward linkage. If an attacker with direct SQLite database access alters any record or removes a row, verification immediately flags the tampering and pinpoints the exact broken record ID.

### 📊 Module 4: Reporting & Scheduling
- **Forensic Scan Reports:** Formats and exports comprehensive, human-readable forensic reports summarizing file changes, detected anomalies, and cryptographic chain status.
- **Background Scan Scheduler:** Single-threaded daemon `ScheduledExecutorService` capable of periodic autonomous integrity scans at configurable intervals.

### 🖥️ Module 5: Graphical User Interface & CLI
- **Modern Swing Desktop GUI:** Responsive, professional interface utilizing `SwingWorker` threads to ensure smooth rendering during I/O operations.
- **Color-Coded Badges:** Immediate visual identification of clean versus compromised states (Green for valid/added, Yellow for modified, Red for deleted/tampered).
- **Headless / CLI Mode:** Direct command-line switches (`--baseline`, `--scan`, `--verify-audit`) enabling scripting, pipeline automation, and automated validation.

---

## 3. System Architecture

```
[ Security Analyst / Grader ]
             │
      ┌──────┴──────────────────────────────────────┐
      │                                             │
      ▼                                             ▼
[ Swing Desktop UI Layer ]                   [ CLI Runner Mode ]
(Dashboard, FIM, Logs, Audit, Config)       (Main --headless / --cli)
      │                                             │
      └──────────────────────┬──────────────────────┘
                             │
                             ▼
                   [ Service Layer ]
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
IntegrityScanner        LogAnalyzer             AuditService
(SHA-256 Stream)     (Rule Engine)          (Hash Chaining)
     │                       │                       │
     ▼                       ▼                       ▼
BaselineDAO / EventDAO   AnomalyDAO              AuditLogDAO
                             │                   (Append-Only)
                             ▼
                [ Embedded SQLite Database ]
                    (data/forensix.db)
```

---

## 4. Technology Stack

| Component | Technology | Rationale |
|---|---|---|
| **Language** | Java 17 (JDK 22 compatible) | Modern standard library (Streams, NIO.2, Records, java.time) |
| **GUI Framework** | Java Swing | Standard JDK desktop toolkit; zero external GUI framework overhead |
| **Database** | SQLite (via `org.xerial:sqlite-jdbc`) | Embedded, zero-configuration file storage; realistic and portable |
| **Cryptography** | `java.security.MessageDigest` | Cryptographically sound SHA-256 implementation bundled in JDK |
| **Build System** | Apache Maven 3.9+ | Standard dependency management and automated test lifecycle |
| **Unit Testing** | JUnit 5 (Jupiter 5.10.2) | Enterprise test framework with parameterized and temp-dir fixtures |
| **Logging** | `java.util.logging` | Built-in rotating file logging to `forensix.log` |

---

## 5. Project Directory Structure

```
forensix/
├── pom.xml                                   # Maven dependencies & build configuration
├── README.md                                 # Complete documentation & usage guide
├── statement.md                              # Problem statement, scope & objectives
├── config.properties                         # Application configuration
├── docs/
│   ├── diagrams/                             # Mermaid architectural and UML diagrams
│   │   ├── architecture.md
│   │   ├── use_case.md
│   │   ├── workflow.md
│   │   ├── sequence_scan.md
│   │   ├── class_diagram.md
│   │   ├── component_diagram.md
│   │   └── er_diagram.md
│   └── report/
│       └── project_report.md                 # Complete academic project report
├── src/
│   ├── main/
│   │   ├── java/com/forensix/
│   │   │   ├── Main.java                     # Application entry point (GUI / CLI)
│   │   │   ├── model/
│   │   │   │   ├── FileRecord.java           # Baseline file metadata
│   │   │   │   ├── FileEvent.java            # ADDED/MODIFIED/DELETED event
│   │   │   │   ├── LogEntry.java             # Parsed log entry
│   │   │   │   ├── Anomaly.java              # Flagged security finding
│   │   │   │   ├── AuditRecord.java          # Cryptographically chained record
│   │   │   │   ├── Scan.java                 # Scan session tracking
│   │   │   │   └── Config.java               # Settings container
│   │   │   ├── dao/
│   │   │   │   ├── DatabaseManager.java      # SQLite connection & schema bootstrapper
│   │   │   │   ├── BaselineDAO.java          # Parameterized baseline operations
│   │   │   │   ├── ScanDAO.java              # Scan session tracking
│   │   │   │   ├── EventDAO.java             # File events persistence
│   │   │   │   ├── AnomalyDAO.java           # Anomalies persistence
│   │   │   │   └── AuditLogDAO.java          # Append-only audit logging (No UPDATE/DELETE)
│   │   │   ├── service/
│   │   │   │   ├── IntegrityScanner.java     # FIM service interface
│   │   │   │   ├── IntegrityScannerImpl.java # FIM baseline & diffing engine
│   │   │   │   ├── LogAnalyzer.java          # Log analyzer interface
│   │   │   │   ├── LogAnalyzerImpl.java      # Rule-based threat detector
│   │   │   │   ├── AuditService.java         # Audit service interface
│   │   │   │   ├── AuditServiceImpl.java     # Hash chaining & verification
│   │   │   │   ├── VerificationResult.java   # Chain verification outcome
│   │   │   │   ├── ReportGenerator.java      # Forensic report builder
│   │   │   │   ├── ScanScheduler.java        # Background scheduled scans
│   │   │   │   └── ServiceContext.java       # Central dependency coordinator
│   │   │   ├── ui/
│   │   │   │   ├── MainWindow.java           # Main Swing desktop shell
│   │   │   │   ├── DashboardPanel.java       # Overview metrics & quick actions
│   │   │   │   ├── FimPanel.java             # File integrity scan browser
│   │   │   │   ├── LogAnalysisPanel.java     # Log anomalies viewer
│   │   │   │   ├── AuditPanel.java           # Cryptographic chain inspector
│   │   │   │   ├── ConfigPanel.java          # Settings & scheduler controls
│   │   │   │   ├── ReportViewerPanel.java    # Report preview & export
│   │   │   │   └── UIHelper.java             # Design system styling & components
│   │   │   └── util/
│   │   │       ├── HashUtil.java             # Chunked streaming SHA-256
│   │   │       ├── PathValidator.java        # Path traversal prevention
│   │   │       └── ConfigLoader.java         # Configuration file management
│   │   └── resources/
│   │       ├── config.properties             # Default properties
│   │       └── sample-logs/
│   │           └── sample-auth.log           # Bundled authentication sample log
│   └── test/
│       └── java/com/forensix/
│           ├── HashUtilTest.java             # Hashing unit tests
│           ├── DatabaseAndDAOTest.java       # SQLite schema & DAO unit tests
│           ├── IntegrityScannerImplTest.java # Baseline diffing unit tests
│           ├── LogAnalyzerImplTest.java      # Rule boundary & parser tests
│           ├── AuditServiceImplTest.java     # Chain verification & tamper tests
│           ├── ConfigAndSchedulerTest.java   # Config & scheduler tests
│           └── SecurityAndEdgeCaseTest.java  # Traversal & concurrency tests
└── data/
    └── forensix.db                           # Local SQLite database (gitignored)
```

---

## 6. Installation & Build

### Prerequisites
- **Java Development Kit (JDK):** Version 17 or higher (`javac -version`).
- **Apache Maven:** Version 3.8 or higher (`mvn -version`).
- **Git:** Installed on local PATH.

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/forensix.git
cd forensix
```

### 2. Build and Package Standalone Fat JAR
```bash
mvn clean package
```
*Builds the project, executes all 24 JUnit 5 tests, and generates `target/forensix-1.0.0.jar` with all dependencies bundled.*

---

## 7. Running the Application

### Option A: Launch Graphical User Interface (GUI)
```bash
java -jar target/forensix-1.0.0.jar
```
*Launches the full desktop interface with Dashboard, FIM Scan, Log Analysis, and Audit Trail panels.*

### Option B: Run via Command-Line Interface (CLI)
You can trigger operations directly in headless or CLI mode:
```bash
# Verify audit chain integrity
java -jar target/forensix-1.0.0.jar --verify-audit

# Establish baseline for a target directory
java -jar target/forensix-1.0.0.jar --baseline ./test-dir

# Execute full security scan (FIM + Log Analysis + Audit Chain)
java -jar target/forensix-1.0.0.jar --scan ./test-dir
```

---

## 8. Step-by-Step Verification Walkthrough

Follow this step-by-step verification to observe real functionality:

1. **Create a Test Directory with Sample Files:**
   ```powershell
   New-Item -ItemType Directory -Path ./test-dir -Force
   Set-Content -Path ./test-dir/config.conf -Value "SERVER_PORT=8080"
   Set-Content -Path ./test-dir/app.bin -Value "BINARY_CONTENT_V1"
   Set-Content -Path ./test-dir/secret.key -Value "ENCRYPTION_KEY_SECRET"
   ```

2. **Establish the Baseline:**
   Launch the app (`java -jar target/forensix-1.0.0.jar`) or run via CLI:
   ```powershell
   java -jar target/forensix-1.0.0.jar --baseline ./test-dir
   ```
   *The toolkit hashes all files and records them in the database.*

3. **Simulate Real Filesystem Modifications (Attack/Tamper):**
   ```powershell
   # 1. Modify a file (simulating trojan/config edit)
   Set-Content -Path ./test-dir/config.conf -Value "SERVER_PORT=9999_MODIFIED"

   # 2. Add an unauthorized file (simulating dropped script)
   Set-Content -Path ./test-dir/added_module.txt -Value "NEW_FILE_CONTENT_ADDED"

   # 3. Delete a file (simulating evidence deletion)
   Remove-Item -Path ./test-dir/secret.key
   ```

4. **Execute Security Scan:**
   Click **"Run Scan Now"** in the UI (or run `java -jar target/forensix-1.0.0.jar --scan ./test-dir`).
   - Observe in the **File Integrity (FIM)** tab:
     - `config.conf` flagged as `MODIFIED` with old and new SHA-256 hashes.
     - `added_module.txt` flagged as `ADDED`.
     - `secret.key` flagged as `DELETED`.
   - Observe in the **Log Analysis** tab:
     - Burst brute-force from `192.168.1.105` flagged (`HIGH`).
     - Blacklisted IP `198.51.100.23` flagged (`CRITICAL`).
     - Off-hours access at `03:15:22` flagged (`MEDIUM`).
     - `root` probe flagged (`HIGH`).
   - Observe in the **Audit Trail** tab:
     - New cryptographic records appended, sealing each finding into the hash chain.

5. **Verify Cryptographic Audit Chain:**
   Click **"Verify Cryptographic Chain"**.
   - Observe the **Green Shield Banner**: `SEALED & INTACT: All records cryptographically verified`.

6. **Demonstrate Tamper Detection (Simulate Malicious DB Modification):**
   In a test database or via SQLite CLI, modify any row in `audit_log`:
   ```sql
   UPDATE audit_log SET payload = 'CLEAN_TAMPERED_LOG' WHERE id = 3;
   ```
   Click **"Verify Cryptographic Chain"** again.
   - Observe the **Red Warning Banner**:
     ```
     TAMPERING DETECTED! Broken Record: #3 (RECORD_HASH_MISMATCH)
     Computed: [b7e3f...] Stored: [01cd5...]
     The database was modified outside authorized application workflows!
     ```

---

## 9. Testing & Quality Assurance

The project includes **24 automated JUnit 5 tests** covering unit, integration, boundary, and security test cases.

Run the test suite:
```bash
mvn test
```

### Test Coverage Summary
- `HashUtilTest`: Known SHA-256 test vectors, empty file handling, 5 MB chunked buffer streaming without heap exhaustion.
- `DatabaseAndDAOTest`: SQLite database schema creation, foreign key constraints, batch transactions, parameterized CRUD.
- `IntegrityScannerImplTest`: Baseline creation, diffing (ADDED, MODIFIED, DELETED, UNCHANGED), empty directory handling.
- `LogAnalyzerImplTest`: 4 vs 5 failed login boundary test, ReDoS tolerance, blacklisted IP detection, off-hours rule.
- `AuditServiceImplTest`: Sequential hash chaining, genesis linking, tamper detection on payload alteration, tamper detection on broken previous hash link.
- `ConfigAndSchedulerTest`: Configuration persistence, background scheduler lifecycle.
- `SecurityAndEdgeCaseTest`: Path traversal sequence (`..`) rejection, concurrent multi-threaded audit logging integrity (8 threads, 200 records).

---

## 10. Security Controls & Guarantees

| Security Property | Implementation Details |
|---|---|
| **Tamper-Evident Audit Log** | Hash chain where $H_n = \text{SHA-256}(\text{Canonical}_n \parallel H_{n-1})$. Detects any unauthorized modification or deletion of past events. |
| **Application-Level Append-Only** | `AuditLogDAO` exposes no `UPDATE` or `DELETE` methods; normal application workflows can only append. |
| **SQL Injection Prevention** | 100% `PreparedStatement` usage with strict `?` binding across all 5 DAO classes. Zero string concatenation. |
| **Path Traversal Prevention** | Strict input validation in `PathValidator` rejecting `..` traversal sequences and symlinks pointing outside the monitored root. |
| **Resource & ReDoS Safety** | Memory-bounded 8 KB streaming file reads; simple bounded regex delimiter patterns for log lines. |
| **Error Sanitization** | UI surfaces sanitized messages; full stack traces and internal exceptions are isolated in `forensix.log`. |

---

## 11. Future Roadmap

- Multi-user role-based access control (RBAC) separating Security Analyst from Read-Only Auditor roles.
- Real-time kernel file event monitoring via `java.nio.file.WatchService`.
- Direct PDF report export with digital cryptographic signatures.
- Remote webhook integration for SIEM alert forwarding.

---

## 12. Authors & Academic Context

- **Author:** Deepayan (Cybersecurity & Digital Forensics Specialization)
- **Course:** Java Programming / VITyarthi Project
- **Toolkit:** FORENSIX — File Integrity & Security Audit Toolkit
- **Date:** September 2026
