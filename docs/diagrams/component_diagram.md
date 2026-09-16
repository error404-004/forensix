# FORENSIX — Component Diagram

```mermaid
graph TB
    subgraph UI_Component ["Component 1: Presentation (Swing UI)"]
        UI_Entry[MainWindow / Panels / Renderers]
    end

    subgraph Service_Component ["Component 2: Business Logic & Processing Services"]
        FIM_Service[FIM Engine: IntegrityScanner]
        Log_Service[Log Analysis Engine: LogAnalyzer]
        Audit_Service[Audit Trail Service: AuditService]
        Report_Service[Reporting Engine: ReportGenerator]
        Scheduler_Service[Background Scheduler: ScanScheduler]
    end

    subgraph DAO_Component ["Component 3: Persistence & Data Access (DAO Layer)"]
        FIM_DAO[BaselineDAO & EventDAO]
        Log_DAO[AnomalyDAO]
        Audit_DAO[AuditLogDAO (Append-Only Enforcement)]
        Scan_DAO[ScanDAO]
        DB_Manager[DatabaseManager (Connection Pool & Schema Bootstrapper)]
    end

    subgraph Storage_Component ["Component 4: Storage Subsystem"]
        SQLite_DB[(Embedded SQLite DB: data/forensix.db)]
    end

    UI_Component -->|Direct Invocations| Service_Component
    Service_Component -->|Parameterized SQL Operations| DAO_Component
    DAO_Component -->|JDBC (PRAGMA foreign_keys = ON)| Storage_Component

    %% Enforce Architectural Directionality: No cyclic or upward calls
```
