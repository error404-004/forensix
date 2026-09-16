# FORENSIX — Use Case Diagram

```mermaid
flowchart LR
    Actor((Security Analyst))

    subgraph Boundaries ["FORENSIX File Integrity & Security Audit Toolkit"]
        UC1[UC-1: Configure Monitored Paths & Thresholds]
        UC2[UC-2: Establish Cryptographic SHA-256 Baseline]
        UC3[UC-3: Execute On-Demand or Scheduled Scan]
        UC4[UC-4: Analyze System / Authentication Logs]
        UC5[UC-5: Review Real-Time Dashboard & Alerts]
        UC6[UC-6: Verify Tamper-Evident Audit Chain Integrity]
        UC7[UC-7: Export Forensic Audit Reports]
    end

    Actor --> UC1
    Actor --> UC2
    Actor --> UC3
    Actor --> UC4
    Actor --> UC5
    Actor --> UC6
    Actor --> UC7

    UC3 ..> UC2 : <<includes baseline comparison>>
    UC3 ..> UC4 : <<triggers log evaluation>>
    UC3 ..> UC6 : <<records hash-chained findings>>
    UC7 ..> UC3 : <<summarizes scan results>>
```
