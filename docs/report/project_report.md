# PROJECT REPORT

## FORENSIX: File Integrity Monitoring & Security Audit Toolkit
**A Cryptographically Sealed, Tamper-Evident Security Audit & Forensic Triage Desktop Application in Java 17**

---

### Course & Academic Details
- **Course Name:** Java Programming
- **Platform:** VITyarthi — Build Your Own Project
- **Specialization Area:** Cybersecurity, Digital Forensics & Incident Response (DFIR)
- **Academic Term:** 2026
- **Student / Author:** Deepayan
- **Project Repository:** FORENSIX (Java Desktop Application)

---

## 1. Introduction

In modern endpoint defense and digital forensics, detecting unauthorized file modifications rapidly is essential for effective incident response. Attackers frequently compromise servers by establishing persistence through modified configuration files, backdoored binaries, or dropped web shells. Furthermore, malicious actors often tamper with local log files or database records to eliminate evidence of their activities (covering tracks).

Traditional host-based defense approaches frequently rely on operating system timestamps (last modified time). However, these timestamps can be trivially manipulated using standard timestomping utilities without changing file contents. Conversely, commercial enterprise File Integrity Monitoring (FIM) platforms like Tripwire or OSSEC require dedicated server infrastructure, active agent daemons, and complex licensing—rendering them impractical for small triage environments, isolated analysis labs, or incident responders needing an immediate, zero-infrastructure forensic toolkit.

**FORENSIX** addresses this gap by implementing an autonomous, pure Java 17 desktop toolkit. It computes cryptographic SHA-256 baselines of filesystem hierarchies using streaming memory-efficient buffers, detects state changes on demand, parses authentication logs to surface security anomalies, and writes every security event into an **application-level append-only, tamper-evident hash-chained audit log**.

---

## 2. Problem Statement

Manual inspection of filesystem modifications is unreliable, error-prone, and cannot scale across complex directory trees. Furthermore, standard logging systems store records in mutable flat files or conventional database tables where an intruder possessing local administrative access can secretly edit, falsify, or delete entries to disguise unauthorized actions.

There is a critical requirement for a lightweight, zero-configuration host integrity monitoring solution that:
1. Cryptographically hashes and baselines files using strong SHA-256 digests.
2. Accurately diffs live file trees against the baseline, categorizing modifications, additions, and deletions.
3. Automatically evaluates authentication and system logs for intrusion patterns such as brute-force attacks and off-hours unauthorized access.
4. Preserves chain-of-custody by maintaining a tamper-evident audit record where any retrospective modification of stored audit entries is mathematically detectable.

---

## 3. Functional Requirements

### 3.1 Module 1: File Integrity Monitoring (FIM)
- **Baseline Creation:** Recursively traverses the designated directory hierarchy, streams every regular file through an 8 KB buffer into a SHA-256 `MessageDigest`, and records the relative path, cryptographic digest, file size, and modification timestamp in the SQLite `baseline_files` table.
- **Differential Scanning:** Inspects live disk contents against stored baselines to classify events into:
  - `ADDED`: New file on disk not present in the baseline.
  - `MODIFIED`: Existing file whose current SHA-256 hash differs from the baseline hash.
  - `DELETED`: Baselined file no longer found on disk.
  - `UNCHANGED`: File with identical path and SHA-256 checksum.
  - `SCAN_ERROR`: Inaccessible or locked file, logged as a finding without halting the scan.

### 3.2 Module 2: Log Analysis & Anomaly Detection
- **Log Ingestion:** Line-by-line streaming of authentication and system logs (`timestamp | user | event | ip`) using bounded token parsing.
- **Rule-Based Threat Detection:**
  - *Rule 1 (Brute-Force Bursts):* Flags $\ge 5$ failed login attempts from the same IP address within a 5-minute sliding window (`HIGH` severity).
  - *Rule 2 (Off-Hours Activity):* Flags logins occurring outside configured business hours (08:00 - 19:00) (`MEDIUM` severity).
  - *Rule 3 (Threat Intelligence Blacklist):* Flags access from configured malicious IP addresses (`CRITICAL` severity).
  - *Rule 4 (Suspicious Account Probing):* Flags failed authentication attempts targeting privileged accounts like `root`, `admin`, `guest`, or `oracle` (`HIGH` severity).

### 3.3 Module 3: Tamper-Evident Hash-Chained Audit Trail
- **Application-Level Append-Only Design:** The database access layer (`AuditLogDAO`) strictly exposes insertion and ordered retrieval methods. No update or delete operations are exposed to application workflows.
- **Cryptographic Hash Chaining:** Every audit record binds its canonical data to the cryptographic hash of the preceding record:
  $$\text{record\_hash}_n = \text{SHA-256}(\text{canonical\_data}_n + "|" + \text{record\_hash}_{n-1})$$
  *(The genesis record links to 64 zeros).*
- **Integrity Verification:** Iterates through the audit log in deterministic order, recomputing hashes and validating backward linkage. If an external attacker alters any past record or deletes a row directly in the database file, verification immediately flags the breach and pinpoints the exact record ID.

### 3.4 Module 4: Configuration, Scheduling & Reporting
- **Dynamic Configuration:** Supports file-based and GUI-based management of monitored paths, rule thresholds, business hours, and blacklist definitions.
- **Background Scan Scheduler:** Utilizes a single-threaded daemon `ScheduledExecutorService` for periodic unattended scans.
- **Forensic Report Generation:** Exports comprehensive text and Markdown forensic reports containing an executive summary, file event tables, log anomaly findings, and cryptographic audit chain status.

---

## 4. Non-Functional Requirements

| Metric | Requirement | Technical Implementation |
|---|---|---|
| **Performance** | Rapid scanning of large directory trees | 8 KB buffered streaming SHA-256 hashing; lazy `Files.walk` traversal; database operations batched in transactions. |
| **Security** | Tamper evidence & injection prevention | Cryptographic SHA-256 hash chain; 100% parameterized `PreparedStatement` SQL queries; strict path traversal input validation. |
| **Reliability** | Fault tolerance during scans & log parsing | Per-file try-catch blocks record `SCAN_ERROR` without aborting scans; malformed log lines are skipped and tracked in error metrics. |
| **Maintainability** | Clean layered architectural separation | Four distinct architectural layers: Presentation (Swing), Service, DAO, and Storage. Loose coupling via Java interfaces. |
| **Usability** | Clear visual feedback and error reporting | Color-coded status indicators (green/amber/red); background `SwingWorker` threads prevent UI freezes during disk I/O. |
| **Resource Efficiency** | Zero external server infrastructure | Embedded SQLite file database (`data/forensix.db`); low heap footprint independent of monitored file size. |

---

## 5. System Architecture

FORENSIX follows a strict multi-tier layered architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                   Presentation Layer (Swing UI)             │
│   MainWindow  •  DashboardPanel  •  FimPanel  •  AuditPanel  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                       Service Layer                         │
│  IntegrityScanner  •  LogAnalyzer  •  AuditService  •  Context│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Data Access Layer (DAO)                  │
│   BaselineDAO  •  ScanDAO  •  EventDAO  •  AuditLogDAO       │
│               (100% Parameterized Statements)                │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                   Storage Subsystem (SQLite)                │
│         data/forensix.db  (PRAGMA foreign_keys = ON)        │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Design Diagrams

Complete Mermaid diagram sources are archived under `docs/diagrams/`:
- **System Architecture Diagram:** `docs/diagrams/architecture.md`
- **Use Case Diagram:** `docs/diagrams/use_case.md`
- **Workflow & Process Flow Diagram:** `docs/diagrams/workflow.md`
- **Scan Sequence Diagram:** `docs/diagrams/sequence_scan.md`
- **Class Diagram:** `docs/diagrams/class_diagram.md`
- **Component Diagram:** `docs/diagrams/component_diagram.md`
- **Database ER Diagram:** `docs/diagrams/er_diagram.md`

---

## 7. Design Decisions & Rationale

1. **Why Java 17 Standard Library over External Frameworks?**
   - Utilizing `java.security.MessageDigest`, `java.nio.file`, and `java.util.logging` ensures zero unnecessary dependency weight, rapid compilation, and guaranteed compatibility across Windows, Linux, and macOS platforms.
2. **Why SQLite over MySQL / PostgreSQL?**
   - Embedded SQLite (`sqlite-jdbc`) provides zero-configuration persistence. Evaluators and analysts can clone the repository, run `mvn clean package`, and immediately execute the application without configuring database servers or credentials.
3. **Why Java Swing for the GUI?**
   - Swing is part of the standard Java desktop runtime. It eliminates extra platform-specific JavaFX module dependencies and provides a stable, cross-platform interface.
4. **Tamper Evidence vs. Physical Immutability:**
   - SQLite is an embedded file on disk; an operating system administrator or local attacker could open the file using raw SQLite tools. Claiming "physical immutability" would be dishonest. Instead, FORENSIX provides **cryptographic tamper evidence**: any modification to previous records breaks the backward-linked SHA-256 hash chain and is immediately flagged during verification.

---

## 8. Implementation Details

### 8.1 Streaming SHA-256 Hashing (`HashUtil.java`)
```java
public static String sha256(Path path) throws IOException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream is = new BufferedInputStream(Files.newInputStream(path), 8192)) {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = is.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
    }
    return bytesToHex(digest.digest());
}
```

### 8.2 Tamper-Evident Hash Chaining (`AuditServiceImpl.java`)
```java
public synchronized AuditRecord record(RecordType type, long refId, String payload) {
    AuditRecord last = auditLogDAO.getLastRecord();
    String prevHash = (last != null) ? last.getRecordHash() : AuditRecord.GENESIS_PREV_HASH;

    AuditRecord newRecord = new AuditRecord(type, refId, payload, prevHash, null);
    String canonicalData = newRecord.getCanonicalData(); // type|refId|payload|createdAt
    String recordHash = HashUtil.sha256(canonicalData + "|" + prevHash);
    newRecord.setRecordHash(recordHash);

    long id = auditLogDAO.insert(newRecord);
    newRecord.setId(id);
    return newRecord;
}
```

### 8.3 Chain Verification Algorithm (`AuditServiceImpl.java`)
```java
public VerificationResult verifyChain() {
    List<AuditRecord> records = auditLogDAO.findAllOrderedById();
    String expectedPrevHash = AuditRecord.GENESIS_PREV_HASH;

    for (AuditRecord record : records) {
        if (!expectedPrevHash.equalsIgnoreCase(record.getPrevHash())) {
            return VerificationResult.tampered(record.getId(), "PREV_HASH_MISMATCH",
                    expectedPrevHash, record.getPrevHash(), "Chain broken at record #" + record.getId());
        }

        String canonicalData = record.getCanonicalData();
        String computedHash = HashUtil.sha256(canonicalData + "|" + record.getPrevHash());
        if (!computedHash.equalsIgnoreCase(record.getRecordHash())) {
            return VerificationResult.tampered(record.getId(), "RECORD_HASH_MISMATCH",
                    computedHash, record.getRecordHash(), "Tampering detected at record #" + record.getId());
        }
        expectedPrevHash = record.getRecordHash();
    }
    return VerificationResult.valid(records.size(), "Audit chain verified intact.");
}
```

---

## 9. Testing Approach & Results

The test suite contains **24 automated JUnit 5 tests**:

| Test Class | Test Focus | Result |
|---|---|---|
| `HashUtilTest` | Standard test vectors, empty file hash, 5 MB streaming without OOM | PASS (4/4) |
| `DatabaseAndDAOTest` | Schema auto-creation, foreign key constraints, batch transactions | PASS (3/3) |
| `IntegrityScannerImplTest` | Baseline establishment, diffing (ADDED, MODIFIED, DELETED, UNCHANGED) | PASS (4/4) |
| `LogAnalyzerImplTest` | 4 vs 5 failed login boundary condition, off-hours, blacklists, ReDoS | PASS (5/5) |
| `AuditServiceImplTest` | Sequential chaining, payload tamper detection, broken link detection | PASS (3/3) |
| `ConfigAndSchedulerTest` | Properties persistence, background scheduler execution & termination | PASS (2/2) |
| `SecurityAndEdgeCaseTest` | Path traversal injection, multi-threaded concurrent audit logging (200 records) | PASS (3/3) |

**Overall Result:** 24 Tests Run, 0 Failures, 0 Errors, 100% Pass Rate.

---

## 10. End-to-End Functional Validation

A complete end-to-end verification of the primary DFIR workflow was executed on the live binary:
1. **Target Directory Baselined:** 3 files created in `test-dir/` (`config.conf`, `app.bin`, `secret.key`).
2. **Filesystem Modifications:**
   - Modified `config.conf` with new port configuration.
   - Added unauthorized web shell `c99_webshell.php`.
   - Deleted sensitive file `secret.key`.
3. **Execution of Full Scan:**
   - All 3 file changes were accurately detected and categorized.
   - Sample authentication log was parsed, detecting 4 anomalies (Brute-force burst, Threat blacklist IP, Off-hours access, Root user probe).
   - Findings were cryptographically sealed into the SQLite audit hash chain.
4. **Audit Verification:**
   - Initial verification confirmed chain validity across all generated records.
   - Intentionally altering row 3 in an isolated test database immediately triggered the red alert banner, accurately identifying record #3 as compromised.

---

## 11. Challenges Faced & Solutions

1. **Deterministic Canonicalization for Audit Hashing:**
   - *Challenge:* Variations in timestamp formats or object serialization across environments could cause false tampering alerts.
   - *Solution:* Implemented a strict canonicalization method `getCanonicalData()` in `AuditRecord` using explicit pipe-delimited fields (`type|refId|payload|createdAt`) prior to hashing.
2. **Multi-Threaded Audit Logging Concurrency:**
   - *Challenge:* Simultaneous background scan events could create race conditions in previous-hash retrieval.
   - *Solution:* Synchronized record append operations in `AuditServiceImpl` and verified thread safety with an 8-thread, 200-record stress test.
3. **Path Traversal Security:**
   - *Challenge:* Checking path traversal sequences (`..`) after normalization allowed malicious paths like `C:/folder/../../windows` to resolve to `C:/windows`.
   - *Solution:* Enforced strict traversal rejection on raw input strings in `PathValidator` prior to any normalization.

---

## 12. Learnings & Key Takeaways

- Practical mastery of Java NIO.2 (`Files.walk`, streams) for memory-efficient directory tree processing.
- Implementation of cryptographic principles (SHA-256, hash chains, Merkle-style backward linkage) in enterprise audit trails.
- Architecture of layered desktop applications using JDBC, DAO design patterns, and Swing multithreading (`SwingWorker`).
- Development of defensive coding habits: 100% parameterized SQL queries, strict path validation, and ReDoS-safe parsing.

---

## 13. References

1. Oracle Java 17 Platform Standard Edition Documentation: `https://docs.oracle.com/en/java/javase/17/`
2. NIST Special Publication 800-92: Guide to Computer Security Log Management.
3. OWASP Top Ten: A01:2021 — Broken Access Control (Path Traversal Prevention).
4. SQLite JDBC Driver Project Documentation: `https://github.com/xerial/sqlite-jdbc`
5. JUnit 5 User Guide: `https://junit.org/junit5/docs/current/user-guide/`
