# FORENSIX — File Integrity & Security Audit Toolkit
### Complete Architecture Blueprint for Antigravity (Java Course Project)

---

## 0. Assumption Note

No project idea was supplied, only the course ("Java"). Given the student's cybersecurity/digital-forensics specialization, this blueprint proposes an original idea that (a) is a genuine, correct application of core Java concepts — OOP, collections, file I/O, exceptions, multithreading, JDBC — and (b) has real technical/security depth rather than being a CRUD demo. If you'd rather build something else, treat everything below as a template to re-run with a different idea.

---

## 1. PROJECT OVERVIEW

**Title:** FORENSIX — File Integrity Monitoring & Security Audit Toolkit

**Description:** A desktop Java application that establishes cryptographic baselines of files/directories, detects unauthorized modification, ingests and analyzes system/application logs for suspicious patterns, and produces tamper-evident audit reports — the core function of a File Integrity Monitor (FIM), a standard blue-team/DFIR control.

**Problem being solved:** Unauthorized or unnoticed file changes (web shells dropped on a server, tampered config/binaries, log deletion to cover tracks) are a common early indicator of compromise. Small teams/labs without commercial FIM tools (Tripwire, OSSEC) have no lightweight way to detect this.

**Why it matters:** Detecting integrity violations quickly is central to incident response and forensic readiness; it directly maps to the student's DFIR/blue-team specialization.

**Target users:** Security analysts / sysadmins running a small lab or server who want a lightweight integrity + log-anomaly tool; secondarily, the student demonstrating DFIR tooling competency.

**Scope:** Local filesystem baselining and monitoring, log-file anomaly detection (from provided/sample logs, not live OS log tailing), tamper-evident audit trail, and reporting — all as a single-machine desktop app.

**Out of scope:** Network-based IDS, live OS syslog daemon integration, distributed/multi-agent monitoring, real-time push alerting (email/SMS), cloud deployment.

**Expected final outcome:** A runnable Java desktop app (Swing UI) backed by SQLite, with baseline/scan/report workflow, that a grader can install, run, tamper with a test file, and see it correctly flagged and logged.

---

## 2. PROBLEM STATEMENT

Manual file integrity checking (eyeballing timestamps, occasional manual hashing) does not scale and is unreliable — modifications can be timestomped, and there is no persistent, queryable, tamper-evident record of what changed and when. Existing enterprise FIM tools are heavyweight, require agents/servers, and are impractical for a student lab or small deployment.

**Proposed solution:** FORENSIX computes and stores cryptographic (SHA-256) baselines for a monitored directory tree, performs on-demand or scheduled scans that diff the current state against the baseline, classifies changes (added/modified/deleted/permission-changed), cross-references a log-analysis module that flags suspicious log patterns (failed-login bursts, off-hours access, known-bad markers), and writes every finding to a hash-chained audit log so the record itself cannot be silently edited.

**Expected benefits:** Fast detection of unauthorized changes, a defensible/tamper-evident audit trail suitable for a forensic report, and a reusable teaching artifact demonstrating applied Java + security engineering.

---

## 3. OBJECTIVES

**Primary**
1. Compute and persist SHA-256 baselines for a chosen directory tree.
2. Detect and classify file-level changes against the baseline on each scan.
3. Parse sample log files and flag suspicious patterns via rule-based detection.
4. Maintain a hash-chained, append-only audit log of all findings.
5. Generate a human-readable audit report (text/PDF-ready) per scan.

**Secondary**
6. Provide a simple Swing dashboard showing baseline status, last scan results, and alerts.
7. Support configurable monitored paths and detection rules via a config file.
8. Provide unit tests covering hashing, diff logic, and rule evaluation.
9. Schedule periodic scans via a background thread (java.util.Timer/ExecutorService).

---

## 4. FUNCTIONAL REQUIREMENTS

### Module 1 — File Integrity Monitoring (FIM)
- **Purpose:** Establish and verify file baselines.
- **Inputs:** Root directory path(s) from config/UI.
- **Processing:** Walk the file tree (`java.nio.file.Files.walk`), compute SHA-256 per file, record path/hash/size/mtime/permissions. On a scan, recompute and diff against the last baseline.
- **Outputs:** List of `FileEvent` objects (ADDED/MODIFIED/DELETED/UNCHANGED) written to DB.
- **Dependencies:** `java.security.MessageDigest`, `java.nio.file`, DB module.
- **Failure cases:** Unreadable file (permission denied) → logged as `SCAN_ERROR`, scan continues; path does not exist → validation error before scan starts.
- **Security considerations:** Never follow symlinks outside the monitored root (path traversal); hash computation must not load entire large files into memory (stream in chunks).

### Module 2 — Log Analysis & Anomaly Detection
- **Purpose:** Parse a log file (auth-log-style: `timestamp | user | event | ip`) and flag suspicious entries.
- **Inputs:** Log file path (sample logs bundled with the project), a rule set (config).
- **Processing:** Line-by-line parse into `LogEntry` objects; apply rules — e.g. ≥5 failed logins from same IP within 5 minutes, access outside configured working hours, access from a blacklisted IP list.
- **Outputs:** List of `Anomaly` objects with severity, written to DB and cross-linked to FIM findings by timestamp proximity.
- **Dependencies:** FIM module (for correlation), DB module.
- **Failure cases:** Malformed log line → skipped and counted in a `parse_errors` metric, not a hard failure.
- **Security considerations:** Treat log content as untrusted input — never execute/interpret it; guard against regex-based ReDoS by using bounded, simple patterns.

### Module 3 — Audit Trail & Tamper-Evident Reporting
- **Purpose:** Record every finding immutably and produce a report.
- **Inputs:** FileEvents, Anomalies, scan metadata.
- **Processing:** Each audit record stores `hash(record_n) = SHA256(record_n_data + hash(record_n-1))` — a hash chain, so any past-record edit breaks the chain (chain-of-custody). A "Verify Audit Log Integrity" function recomputes the chain and reports the first broken link.
- **Outputs:** Persisted audit log (DB) + generated report file (plain text/Markdown) summarizing a scan.
- **Dependencies:** DB module.
- **Failure cases:** DB write failure → operation retried once, then surfaced to UI as a critical error (must not fail silently).
- **Security considerations:** This is the module's whole point — records must be append-only at the application layer (no UPDATE/DELETE exposed on audit rows).

### Module 4 — Configuration & Scheduling (secondary)
- **Purpose:** Let the user set monitored paths, rule thresholds, and scan interval.
- **Inputs:** UI form / config file (`config.properties`).
- **Processing:** Validate paths exist and are readable; validate numeric thresholds; start/stop a background `ScheduledExecutorService` for periodic scans.
- **Outputs:** Updated in-memory `Config` object; timer state.
- **Dependencies:** All above modules consume `Config`.
- **Failure cases:** Invalid config value → reject with a specific error, keep last-known-good config active.
- **Security considerations:** Config file is local, but validate all paths against a whitelist root to prevent monitoring arbitrary system paths accidentally.

---

## 5. NON-FUNCTIONAL REQUIREMENTS

| Requirement | How achieved |
|---|---|
| **Performance** | Stream-based hashing (8KB buffer chunks); scan of ~5,000 files completes in a few seconds on a student laptop; DB writes batched per scan, not per file. |
| **Security** | SHA-256 (not MD5/SHA-1) for hashing; hash-chained audit log; parameterized JDBC queries only (no string-concatenated SQL) to prevent injection; input validation on all paths/config values; no secrets stored (no auth in v1, documented as a future enhancement). |
| **Reliability** | Every scan wrapped in try/catch per file so one bad file doesn't abort the whole scan; DB operations use transactions so a scan's results are all-or-nothing. |
| **Usability** | Swing dashboard shows baseline status, last scan summary, and a color-coded alert list (red = anomaly, green = clean) rather than raw logs. |
| **Maintainability** | Layered package structure (model / service / dao / ui / util), interfaces for `IntegrityScanner`, `LogAnalyzer`, `AuditLogger` so implementations are swappable; Javadoc on all public methods. |
| **Logging/Monitoring** | Application-level logging via `java.util.logging` to a rotating file (`forensix.log`), separate from the tamper-evident audit DB log. |
| **Resource efficiency** | SQLite (embedded, no server process); directory walk is lazy (`Files.walk` stream, not eager full-tree load into memory). |

---

## 6. USER ROLES

| Actor | Permissions | Responsibilities | Accessible Modules | Restrictions |
|---|---|---|---|---|
| **Security Analyst (primary/only role, v1)** | Full: configure paths, run baseline, run scans, view alerts, verify audit chain, export reports | Set up monitoring, review findings, respond to alerts | All 4 modules | Cannot edit/delete audit log entries (enforced at DAO layer — no delete/update methods exposed for audit table) |

*(Single-role app is intentional and honest for scope — a multi-user auth system would be scope creep for a Java-course FIM tool. Documented as a future enhancement, not faked.)*

---

## 7. COMPLETE SYSTEM WORKFLOW

**Normal workflow:**
1. User launches app → Swing UI loads, reads `config.properties`.
2. User selects/confirms monitored directory → clicks "Create Baseline".
3. FIM module walks tree, hashes files, writes baseline rows to DB.
4. User (or scheduler) triggers "Run Scan".
5. FIM module recomputes hashes, diffs vs baseline → FileEvents.
6. Log Analyzer parses configured log file → Anomalies.
7. Both feed the Audit module → hash-chained records written to DB.
8. Report generator produces a scan report; UI refreshes dashboard with results.

**Failure/error workflow:**
- Invalid/unreadable path at baseline time → UI shows validation error, no partial baseline written.
- File unreadable mid-scan → event logged as `SCAN_ERROR` for that file, scan continues, summarized in report.
- DB unavailable → operation aborted with a clear UI error; nothing partially committed (transaction rollback).
- Audit chain verification fails → UI shows a prominent tamper-detected warning with the first broken record ID.

---

## 8. SYSTEM ARCHITECTURE

Layered desktop architecture:

```
[User]
   |
   v
[Swing UI Layer]  (Dashboard, Config Panel, Report Viewer)
   |
   v
[Service Layer]
   +-- IntegrityScanner (Module 1)
   +-- LogAnalyzer      (Module 2)
   +-- AuditService      (Module 3)
   +-- ConfigService/Scheduler (Module 4)
   |
   v
[DAO Layer]  (BaselineDAO, EventDAO, AnomalyDAO, AuditLogDAO)
   |
   v
[SQLite Database]  (forensix.db)

[Filesystem]  <--- read by IntegrityScanner
[Log files]   <--- read by LogAnalyzer
[Report files] <--- written by ReportGenerator
[forensix.log] <--- written by application Logger (java.util.logging)
```

**Why each layer exists:** UI is decoupled from business logic so scanning/analysis logic is independently testable (JUnit) without a display; DAO layer isolates all SQL so it's the single place to enforce parameterized queries and append-only audit access; SQLite chosen over a client-server DB to keep the project runnable with zero external services.

---

## 9. TECHNOLOGY STACK

| Technology | Used by | Why | Alternative | Why not |
|---|---|---|---|---|
| **Java 17** | Whole app | Course requirement; modern language features (records, streams, NIO.2) | Java 8 | Older, fewer stdlib conveniences |
| **Swing** | UI layer | Ships with the JDK, no extra dependency, standard for a Java-course desktop app | JavaFX | Extra module setup overhead not worth it for scope |
| **SQLite (JDBC, `org.xerial:sqlite-jdbc`)** | DAO layer | Embedded, zero-config, file-based — realistic for a student project | PostgreSQL/MySQL | Requires a running server; unnecessary ops overhead |
| **Maven** | Build | Standard dependency/build management, easy for a grader to `mvn package` and run | Gradle | Maven is more common in Java coursework |
| **JUnit 5** | Testing | Standard Java testing framework | TestNG | Less common in coursework context |
| **java.security.MessageDigest (SHA-256)** | Module 1 | Built into JDK, cryptographically sound hashing | Apache Commons Codec | No need for an extra dependency |
| **java.util.logging** | App logging | Built into JDK, sufficient for this scope | SLF4J+Logback | Adds dependency weight not justified here |

Kept intentionally lean — no Spring, no web server, no external message broker; none of that is justified by the actual requirements.

---

## 10. COMPLETE FOLDER STRUCTURE

```
forensix/
├── src/
│   ├── main/
│   │   ├── java/com/forensix/
│   │   │   ├── Main.java                     # App entry point, boots UI
│   │   │   ├── model/
│   │   │   │   ├── FileRecord.java           # baseline row: path, hash, size, mtime
│   │   │   │   ├── FileEvent.java            # ADDED/MODIFIED/DELETED/UNCHANGED
│   │   │   │   ├── LogEntry.java             # parsed log line
│   │   │   │   ├── Anomaly.java              # flagged log finding + severity
│   │   │   │   └── AuditRecord.java          # hash-chained audit row
│   │   │   ├── service/
│   │   │   │   ├── IntegrityScanner.java     # interface (Module 1)
│   │   │   │   ├── IntegrityScannerImpl.java
│   │   │   │   ├── LogAnalyzer.java          # interface (Module 2)
│   │   │   │   ├── LogAnalyzerImpl.java
│   │   │   │   ├── AuditService.java         # interface (Module 3)
│   │   │   │   ├── AuditServiceImpl.java     # hash-chaining logic
│   │   │   │   ├── ReportGenerator.java
│   │   │   │   └── ScanScheduler.java        # Module 4, ExecutorService
│   │   │   ├── dao/
│   │   │   │   ├── BaselineDAO.java
│   │   │   │   ├── EventDAO.java
│   │   │   │   ├── AnomalyDAO.java
│   │   │   │   ├── AuditLogDAO.java          # append-only: no update/delete
│   │   │   │   └── DatabaseManager.java      # connection + schema init
│   │   │   ├── ui/
│   │   │   │   ├── MainWindow.java
│   │   │   │   ├── ConfigPanel.java
│   │   │   │   ├── DashboardPanel.java
│   │   │   │   └── ReportViewerPanel.java
│   │   │   └── util/
│   │   │       ├── HashUtil.java             # streaming SHA-256
│   │   │       └── ConfigLoader.java
│   │   └── resources/
│   │       ├── config.properties
│   │       └── sample-logs/
│   │           └── sample-auth.log
│   └── test/
│       └── java/com/forensix/
│           ├── HashUtilTest.java
│           ├── IntegrityScannerImplTest.java
│           ├── LogAnalyzerImplTest.java
│           └── AuditServiceImplTest.java
├── docs/
│   ├── diagrams/                             # Mermaid .md files, see §20
│   └── report/                               # source for the PDF project report
├── data/
│   └── forensix.db                           # created at runtime (gitignored)
├── README.md
├── statement.md
├── pom.xml
└── .gitignore
```

**Counts as ≥10 meaningful classes/files**, satisfying the module minimum, with a clean 4-layer package split.

---

## 11. MODULE / CLASS DESIGN

| Class | Purpose | Key methods | Depends on |
|---|---|---|---|
| `HashUtil` | Streaming SHA-256 of a file | `sha256(Path): String` | — |
| `IntegrityScannerImpl` | Baseline + scan logic | `createBaseline(Path)`, `scan(Path): List<FileEvent>` | `HashUtil`, `BaselineDAO`, `EventDAO` |
| `LogAnalyzerImpl` | Parse + rule-evaluate logs | `parse(Path): List<LogEntry>`, `evaluate(List<LogEntry>): List<Anomaly>` | `AnomalyDAO`, `Config` |
| `AuditServiceImpl` | Hash-chained audit writes + verification | `record(Object finding)`, `verifyChain(): VerificationResult` | `AuditLogDAO` |
| `ReportGenerator` | Turns a scan's data into a report file | `generate(ScanResult): Path` | `EventDAO`, `AnomalyDAO`, `AuditLogDAO` |
| `ScanScheduler` | Periodic scan trigger | `start(interval)`, `stop()` | `IntegrityScanner`, `LogAnalyzer` |
| `DatabaseManager` | Connection + schema bootstrap | `getConnection()`, `initSchema()` | SQLite JDBC |
| `BaselineDAO` / `EventDAO` / `AnomalyDAO` / `AuditLogDAO` | Parameterized CRUD (audit: insert+read only) | `insert`, `findAll`, `findByScanId` | `DatabaseManager` |
| `MainWindow` | Swing shell, nav between panels | — | all `ui/*` panels |

---

## 12. DATABASE DESIGN

```
baseline_files
  id INTEGER PK
  path TEXT NOT NULL
  hash TEXT NOT NULL
  size_bytes INTEGER
  last_modified TEXT
  created_at TEXT

scans
  id INTEGER PK
  started_at TEXT
  finished_at TEXT
  status TEXT

file_events
  id INTEGER PK
  scan_id INTEGER FK -> scans(id)
  path TEXT NOT NULL
  event_type TEXT   -- ADDED/MODIFIED/DELETED/UNCHANGED/SCAN_ERROR
  old_hash TEXT
  new_hash TEXT
  detected_at TEXT

anomalies
  id INTEGER PK
  scan_id INTEGER FK -> scans(id)
  log_entry TEXT
  rule_triggered TEXT
  severity TEXT
  detected_at TEXT

audit_log
  id INTEGER PK
  record_type TEXT      -- FILE_EVENT / ANOMALY / SCAN
  record_ref_id INTEGER
  payload TEXT
  prev_hash TEXT
  record_hash TEXT NOT NULL   -- SHA256(payload + prev_hash)
  created_at TEXT
  -- No UPDATE/DELETE statements exist anywhere in AuditLogDAO
```

**Relationships:** `scans (1) — (many) file_events`, `scans (1) — (many) anomalies`, `audit_log` references either via `record_type` + `record_ref_id`.

**Stored:** file paths, hashes, log-derived metadata, timestamps.
**Not stored:** actual file contents, raw credentials, PII beyond what's already in sample logs (usernames/IPs — documented as synthetic/sample data only).
**Retention:** all data is local to `data/forensix.db`; no external transmission.
**Security:** parameterized queries only; DB file permissions restricted at the OS level (documented in README, not enforced by app since that's OS-level).

---

## 13. API DESIGN

Not applicable — this is a standalone desktop app with no network-exposed API. The Service Layer interfaces (`IntegrityScanner`, `LogAnalyzer`, `AuditService`) serve as the internal contract the UI and tests call against, documented with Javadoc instead of REST specs.

---

## 14. SECURITY ARCHITECTURE

- **Input validation:** every path from UI/config validated (exists, is under an allowed root, no `..` traversal) before use.
- **SQL injection prevention:** 100% `PreparedStatement` usage in DAO layer, no string-concatenated SQL anywhere.
- **Tamper-evident logging:** hash-chained audit table (see §12) — the actual security-relevant control of this project.
- **Cryptographic hashing:** SHA-256 for file integrity, not a weak/legacy algorithm.
- **Least privilege:** audit DAO exposes no update/delete; app runs with normal user privileges, no elevation requested.
- **Secure error handling:** stack traces never shown in UI, only a generic message + full detail to `forensix.log`.
- **Resource limits:** streamed file reads (bounded buffer) to avoid memory exhaustion on large files; ReDoS-safe simple regex in log parsing.

No JWT/AES/blockchain bolted on for buzzword reasons — this app has no network layer or auth system in v1, so those controls would be theater; that's stated explicitly rather than faked.

---

## 15. THREAT MODEL (STRIDE, abbreviated)

| Asset | Threat | Category | Mitigation |
|---|---|---|---|
| Baseline/audit DB | Attacker directly edits SQLite file to hide tampering | Tampering | Hash-chain makes any edit to a past record detectable on next `verifyChain()` |
| Monitored files | Attacker modifies file then restores mtime (timestomping) | Tampering | Detection relies on content hash, not mtime, so timestomping doesn't evade it |
| Log input | Malicious/malformed log content crashes parser | Denial of Service | Per-line try/catch, bounded regex, parse errors counted not fatal |
| Config file | Path traversal via crafted config path | Elevation of Privilege (scope) | Root-path whitelist validation before any file walk |
| App logs (`forensix.log`) | Info disclosure of internal paths | Information Disclosure | Log to local file only, never displayed to unauthenticated party (n/a — single local user) |

---

## 16. ERROR HANDLING

- **Input validation errors** → UI dialog, specific message, operation not attempted.
- **Application errors** (NPE, logic bugs) → caught at UI action boundary, generic "operation failed" shown, full trace to `forensix.log`.
- **DB errors** → transaction rolled back, UI shows "database error, no changes saved."
- **File errors** (permission denied, not found) → per-file, logged as `SCAN_ERROR`, scan continues.
- **What user sees:** short, non-technical message. **What's logged:** full exception + context. **Never exposed to UI:** stack traces, file-system internals, SQL text.

---

## 17. LOGGING & MONITORING

- **App log (`forensix.log`, java.util.logging, rotating):** INFO for scan start/end, WARNING for recoverable errors, SEVERE for failures.
- **Audit log (DB, hash-chained):** every FileEvent, Anomaly, and scan summary — this is the security-relevant, tamper-evident record, distinct from the app log.
- **Never logged:** none (no secrets exist in this app's scope, but if extended with auth, this line is where password/token exclusion would be enforced).

---

## 18. TESTING STRATEGY

| Module | Test cases |
|---|---|
| `HashUtil` | Known-input SHA-256 matches expected value; empty file; large file streams without OOM. |
| `IntegrityScannerImpl` | Baseline of a temp dir matches disk state; scan after modifying a file returns `MODIFIED`; scan after deleting a file returns `DELETED`; scan of unchanged dir returns empty diff. |
| `LogAnalyzerImpl` | 5 failed logins in 5 min triggers anomaly; 4 does not (boundary test); malformed line doesn't crash parser. |
| `AuditServiceImpl` | Chain verifies clean on normal writes; manually corrupting one DB row is detected by `verifyChain()` with correct broken-record ID. |
| Negative/edge cases | Nonexistent monitored path rejected at config time; empty log file handled; scanning a dir with zero files produces a valid empty-baseline result. |

JUnit 5, run via `mvn test`.

---

## 19. UI / UX ARCHITECTURE

| Screen | Purpose | Components | Actions | States |
|---|---|---|---|---|
| **Dashboard** | At-a-glance status | Baseline status card, last-scan summary, alert list | "Run Scan", "Verify Audit Log" | Empty (no baseline yet), Loading (scan running), Populated, Alert (red banner if anomalies found) |
| **Config Panel** | Set monitored path, log path, rule thresholds, scan interval | Path picker, numeric fields, save button | "Save Config", "Create Baseline" | Validation-error state per field |
| **Report Viewer** | View/export a past scan's report | Scan list, report text pane, export button | "Export Report" | Empty (no scans yet), Loaded |

Straightforward Swing desktop UI — not over-designed, but organized enough to look like a working security tool rather than a toy.

---

## 20. DIAGRAMS REQUIRED

**System Architecture Diagram** — entities: UI, Service Layer (4 services), DAO Layer (4 DAOs), SQLite DB, Filesystem, Log files. Flow: UI → Service → DAO → DB; Service also reads Filesystem/Logs directly.

**Use Case Diagram** — actor: Security Analyst. Use cases: Configure Monitoring, Create Baseline, Run Scan, View Dashboard, Verify Audit Log, Export Report.

**Workflow Diagram** — see §7 (normal + failure paths).

**Sequence Diagram (Run Scan):** UI → IntegrityScannerImpl.scan() → HashUtil.sha256() (loop per file) → BaselineDAO.findAll() (compare) → EventDAO.insert() → LogAnalyzerImpl.evaluate() → AnomalyDAO.insert() → AuditServiceImpl.record() (chained) → ReportGenerator.generate() → UI refresh.

**Class Diagram:** as in §11, showing interface/impl pairs and DAO dependencies.

**Component Diagram:** UI Layer, Service Layer, DAO Layer, SQLite DB as four components with directional arrows top-to-bottom, no upward calls.

**ER Diagram:** as in §12 (`scans` 1—N `file_events`, `scans` 1—N `anomalies`, `audit_log` referencing both by type+id).

Mermaid source for each should be generated by Antigravity and stored under `docs/diagrams/*.md`.

---

## 21. DATA FLOW

```
Filesystem → HashUtil (SHA-256) → BaselineDAO/EventDAO → SQLite
Log file → LogAnalyzer (parse+rules) → AnomalyDAO → SQLite
FileEvents + Anomalies → AuditServiceImpl (hash-chain) → audit_log (SQLite)
SQLite (scan data) → ReportGenerator → report file (docs/reports/*.txt)
```

Sensitive data (usernames/IPs from logs) exists in `anomalies.log_entry` and the audit payload — documented in README as synthetic/sample data only, never real production logs.

---

## 22. PERFORMANCE CONSIDERATIONS

- Baseline/scan of ~5,000 files with average size <1MB: target under 10 seconds on a typical student laptop.
- Hashing streamed in 8KB chunks — memory usage independent of file size.
- DB writes batched in a single transaction per scan, not per file, to avoid thousands of tiny commits.
- No concurrent-user concern (single local user, single-process app).

---

## 23. DEPLOYMENT ARCHITECTURE

- **Local development:** clone repo, `mvn clean install`, run `Main.java` from IDE or `java -jar target/forensix.jar`.
- **"Production":** same — this is a local desktop tool, no server deployment needed.
- **Environment variables/config:** `src/main/resources/config.properties` (monitored path, log path, thresholds, scan interval) — no secrets, so no `.env` needed.
- **Database setup:** `DatabaseManager.initSchema()` creates `data/forensix.db` and tables on first run if absent — zero manual setup.
- **Build:** Maven (`pom.xml`), produces a runnable shaded JAR via `maven-shade-plugin`.

---

## 24. GIT / GITHUB STRATEGY

- **Branches:** `main` (stable), `dev` (integration), feature branches per module: `feature/fim-module`, `feature/log-analyzer`, `feature/audit-log`, `feature/ui`.
- **Commit strategy:** one logical change per commit, conventional messages (`feat:`, `fix:`, `test:`, `docs:`).
- **Suggested milestones:** scaffold+DB schema → FIM module + tests → Log Analyzer + tests → Audit hash-chain + tests → Swing UI wiring → README/report/diagrams.
- **`.gitignore`:** `target/`, `data/forensix.db`, `*.log`, IDE files (`.idea/`, `*.iml`).

---

## 25. README.md SPECIFICATION

Sections: Project title & one-line description; Overview; Features (bullet per module); Architecture (paste §8 diagram); Tech stack (table from §9); Installation (`git clone`, `mvn clean install`); Configuration (`config.properties` fields explained); Running (`java -jar ...`); Testing (`mvn test`); Screenshots (dashboard, alert view); API documentation (n/a — note why); Security (summary of §14); Project structure (paste §10 tree); Future enhancements (§32).

---

## 26. statement.md SPECIFICATION

Content: Problem statement (§2, condensed to 2–3 sentences); Scope (from §1); Target users (security analyst / sysadmin, small lab); High-level features (baseline, scan/diff, log anomaly detection, tamper-evident audit log, reporting).

---

## 27. PROJECT REPORT SPECIFICATION

| Report chapter | Content | Diagrams/screenshots |
|---|---|---|
| Introduction | §1 context, why FIM matters | — |
| Problem Statement | §2 | — |
| Functional Requirements | §4 | — |
| Non-functional Requirements | §5 table | — |
| System Architecture | §8 | Architecture diagram |
| Design Diagrams | — | Use case, sequence, class, ER (§20) |
| Design Decisions & Rationale | Why SQLite/Swing/no-auth-in-v1 (§9, §6) | — |
| Implementation Details | Module walkthroughs (§4, §11) | Key code snippets |
| Screenshots / Results | Dashboard before/after tampering a test file, alert triggering | Screenshots |
| Testing Approach | §18 | Test run output |
| Challenges Faced | Fill in during build (e.g. hash-chain edge cases) | — |
| Learnings & Key Takeaways | Fill in post-build | — |
| Future Enhancements | §32 | — |
| References | JDK docs, SQLite JDBC docs, OWASP references used | — |

---

## 28. IMPLEMENTATION ROADMAP FOR ANTIGRAVITY

**Phase 0 — Environment setup**
Tasks: init Maven project, add `sqlite-jdbc` + JUnit 5 dependencies to `pom.xml`, verify `mvn compile` succeeds.
Files: `pom.xml`. Validation: clean build with no code yet.

**Phase 1 — Project scaffolding**
Tasks: create package structure (§10), stub classes with Javadoc, `Main.java` prints "FORENSIX starting."
Files: all package dirs + stub classes. Validation: `mvn compile` succeeds, app runs and exits.

**Phase 2 — Database**
Tasks: implement `DatabaseManager`, schema DDL (§12), `BaselineDAO`, `EventDAO`, `AnomalyDAO`, `AuditLogDAO` with parameterized CRUD (no update/delete on audit).
Files: `dao/*`. Validation: unit test creates schema, inserts/reads a row.

**Phase 3 — Integrity Monitoring module**
Tasks: `HashUtil` (streaming SHA-256), `IntegrityScannerImpl` baseline + scan/diff logic.
Files: `util/HashUtil.java`, `service/IntegrityScanner*.java`. Validation: `HashUtilTest`, `IntegrityScannerImplTest` pass (create temp dir, modify a file, confirm `MODIFIED` detected).

**Phase 4 — Log Analysis module**
Tasks: `LogEntry` model, `LogAnalyzerImpl` parser + rule engine, bundle `sample-auth.log`.
Files: `model/LogEntry.java`, `model/Anomaly.java`, `service/LogAnalyzer*.java`, `resources/sample-logs/sample-auth.log`. Validation: `LogAnalyzerImplTest` passes on sample log.

**Phase 5 — Audit Trail module**
Tasks: `AuditServiceImpl` hash-chaining logic + `verifyChain()`.
Files: `service/AuditService*.java`. Validation: `AuditServiceImplTest` — chain verifies clean; corrupted row detected.

**Phase 6 — Reporting**
Tasks: `ReportGenerator` produces a readable text report per scan.
Files: `service/ReportGenerator.java`. Validation: manual scan produces a well-formed report file.

**Phase 7 — Config & Scheduler**
Tasks: `ConfigLoader`, `config.properties`, `ScanScheduler` (ExecutorService-based periodic scans).
Files: `util/ConfigLoader.java`, `service/ScanScheduler.java`, `resources/config.properties`. Validation: scheduler triggers a scan on interval in a test.

**Phase 8 — Swing UI**
Tasks: `MainWindow`, `ConfigPanel`, `DashboardPanel`, `ReportViewerPanel`, wire to service layer.
Files: `ui/*`. Validation: manual walkthrough — configure path, baseline, tamper a file, scan, see it flagged.

**Phase 9 — Security hardening pass**
Tasks: audit all DAO SQL for parameterization, add path-traversal validation, review error messages for leakage.
Files: touch-ups across `dao/`, `util/`, `ui/`. Validation: manual review checklist from §14.

**Phase 10 — Testing completion**
Tasks: fill remaining edge-case tests from §18.
Files: `src/test/**`. Validation: `mvn test` all green.

**Phase 11 — Documentation & diagrams**
Tasks: write README.md, statement.md, generate Mermaid diagrams into `docs/diagrams/`, assemble report source in `docs/report/`.
Files: `README.md`, `statement.md`, `docs/**`. Validation: README steps followed on a clean clone actually work.

---

## 29. ANTIGRAVITY BUILD CONTRACT

1. Follow this architecture exactly unless a genuine technical conflict is found (note it if so).
2. Build the complete project end-to-end, not a partial prototype.
3. Create every file/folder in §10.
4. Implement all four functional modules fully.
5. Implement the Swing UI wired to real service calls (no mock data in the UI).
6. Implement input validation and error handling per §16.
7. Implement every control in §14 — especially parameterized SQL and the audit hash-chain.
8. Write the tests in §18 as real JUnit 5 tests, not stubs.
9. Run the application locally and confirm the full workflow in §7 works end-to-end.
10. Fix all implementation errors found during that run-through.
11. There is no external API, so instead verify every service-layer method against its test.
12. Verify the full workflow: baseline → tamper a file → scan → see it flagged → verify audit chain → export report.
13. Update README.md to match what was actually built.
14. Create statement.md per §26.
15. Create the diagrams in `docs/diagrams/` (Mermaid) per §20.
16. Generate Mermaid source for each diagram listed in §20.
17. Never leave TODO placeholders in the four core modules.
18. Never hardcode a fake scan result or fake "detected anomaly" — all findings must come from real hashing/parsing logic run against real test data.
19. Never quietly drop the hash-chain audit requirement — it's the project's core security differentiator.
20. Keep the project runnable from a clean `git clone` + `mvn clean install` + `java -jar ...`.

---

## 30. ACCEPTANCE CRITERIA

- [ ] Application builds with `mvn clean install` and starts successfully
- [ ] SQLite database initializes automatically on first run
- [ ] Baseline creation works on a real directory
- [ ] Scan correctly detects ADDED/MODIFIED/DELETED files against baseline
- [ ] Log analyzer correctly flags a seeded suspicious pattern in `sample-auth.log`
- [ ] Audit log hash-chain verifies clean on normal operation
- [ ] Audit log hash-chain correctly detects a manually corrupted row
- [ ] Report generation produces a readable report file per scan
- [ ] Input validation rejects an invalid/nonexistent monitored path
- [ ] All JUnit tests pass (`mvn test`)
- [ ] README complete and its install steps work on a clean clone
- [ ] statement.md complete
- [ ] All required diagrams present in `docs/diagrams/`
- [ ] Screenshots captured (dashboard clean state, dashboard alert state)
- [ ] GitHub repository organized per §10, with meaningful commit history

---

## 31. RISK ANALYSIS

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Hash-chain logic bug (chain doesn't correctly detect corruption) | Medium | High — undermines the project's core claim | Write the corruption-detection test (§18) first, before UI work |
| Swing UI takes longer than expected | Medium | Medium | UI is last phase (§28 Phase 8); core logic is fully testable/gradeable without it |
| SQLite JDBC dependency/version issues | Low | Medium | Pin exact version in `pom.xml`, test `mvn clean install` early (Phase 0) |
| Scope creep (adding auth, network features) | Medium | Medium | §1 "Out of scope" is explicit; resist mid-build additions not in this blueprint |
| Time constraints near deadline | Medium | High | Phases 0–7 (backend) are the gradeable core; UI/docs (8–11) can compress if needed without losing functional-module credit |

---

## 32. FUTURE ENHANCEMENTS

- Multi-user auth with role-based access (Analyst vs read-only Auditor)
- Live OS log tailing instead of static sample-log parsing
- Email/webhook alerting on critical anomalies
- Pluggable detection rule engine (externalized rule DSL instead of hardcoded thresholds)
- PDF export for reports (currently plain text/Markdown)

---

## 33. FINAL ARCHITECTURE SUMMARY

**A. One-page summary:** FORENSIX is a Java Swing desktop File Integrity Monitor: it baselines a directory with SHA-256 hashes, detects changes on scan, cross-references log-based anomaly detection, and records every finding in a tamper-evident hash-chained audit log, backed by embedded SQLite.

**B. Tech stack:** Java 17, Swing, SQLite (JDBC), Maven, JUnit 5, `java.security`/`java.util.logging` (all standard-library except the JDBC driver).

**C. Modules:** File Integrity Monitoring, Log Analysis & Anomaly Detection, Audit Trail & Reporting, Configuration & Scheduling.

**D. Database:** 5 tables (`baseline_files`, `scans`, `file_events`, `anomalies`, `audit_log`), audit table append-only by design.

**E. Security:** SHA-256 hashing, hash-chained tamper-evident logging, parameterized SQL, path-traversal validation, least-privilege DAO design — every control has a stated reason (§14).

**F. Implementation roadmap:** 12 phases (§28), Phase 0–2 setup/DB, 3–6 the four functional modules, 7 config/scheduler, 8 UI, 9–11 hardening/testing/docs.

**G. Acceptance checklist:** §30.

---

## WHAT I SHOULD GIVE TO ANTIGRAVITY

1. This entire document (`forensix-blueprint.md`).
2. The VITyarthi assignment brief (for grading-rubric context, so Antigravity keeps report/README requirements aligned).
3. A one-line note: "Follow the blueprint exactly; ask me only if you hit a genuine technical conflict it doesn't resolve."
4. Nothing else is needed — the blueprint is self-contained (folder structure, schema, class list, phased plan, and acceptance criteria are all specified above).
