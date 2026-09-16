package com.forensix.service;

import com.forensix.model.AuditRecord;

import java.util.List;

/**
 * Service contract for tamper-evident hash-chained audit logging and verification.
 */
public interface AuditService {

    /**
     * Appends a new event or finding to the cryptographic audit hash-chain.
     *
     * @param type type of audit entry
     * @param refId foreign ID referencing file_event, anomaly, or scan
     * @param payload canonical description / details of the event
     * @return created AuditRecord with computed hash
     */
    AuditRecord record(AuditRecord.RecordType type, long refId, String payload);

    /**
     * Traverses the entire audit log from genesis record to the latest record,
     * recomputing and verifying each link in the cryptographic hash-chain.
     *
     * @return VerificationResult indicating whether the log is intact or where tampering occurred
     */
    VerificationResult verifyChain();

    /**
     * Retrieves all audit records in chronological order.
     */
    List<AuditRecord> getAuditTrail();

    /**
     * Returns total number of audit records stored.
     */
    int getRecordCount();
}
