package com.forensix.service;

import com.forensix.dao.AuditLogDAO;
import com.forensix.model.AuditRecord;
import com.forensix.util.HashUtil;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of AuditService.
 * Maintains a cryptographic tamper-evident hash chain across all recorded audit entries.
 */
public class AuditServiceImpl implements AuditService {
    private static final Logger LOGGER = Logger.getLogger(AuditServiceImpl.class.getName());

    private final AuditLogDAO auditLogDAO;

    public AuditServiceImpl(AuditLogDAO auditLogDAO) {
        this.auditLogDAO = auditLogDAO;
    }

    @Override
    public synchronized AuditRecord record(AuditRecord.RecordType type, long refId, String payload) {
        if (type == null) {
            throw new IllegalArgumentException("Audit RecordType cannot be null");
        }

        // Determine prev_hash from the latest record in the database
        AuditRecord last = auditLogDAO.getLastRecord();
        String prevHash = (last != null) ? last.getRecordHash() : AuditRecord.GENESIS_PREV_HASH;

        AuditRecord newRecord = new AuditRecord(type, refId, payload, prevHash, null);

        // Compute SHA-256 over canonical data + previous record hash
        String canonicalData = newRecord.getCanonicalData();
        String recordHash = HashUtil.sha256(canonicalData + "|" + prevHash);
        newRecord.setRecordHash(recordHash);

        long id = auditLogDAO.insert(newRecord);
        newRecord.setId(id);

        LOGGER.info("Appended audit record #" + id + " [" + type + "]. Hash: " + recordHash.substring(0, 16) + "...");
        return newRecord;
    }

    @Override
    public VerificationResult verifyChain() {
        LOGGER.info("Starting cryptographic audit chain integrity verification...");
        List<AuditRecord> records = auditLogDAO.findAllOrderedById();

        if (records.isEmpty()) {
            return VerificationResult.valid(0, "Audit log is empty (0 records).");
        }

        String expectedPrevHash = AuditRecord.GENESIS_PREV_HASH;

        for (AuditRecord record : records) {
            long recordId = record.getId();

            // Step 1: Verify linkage to previous record
            if (!expectedPrevHash.equalsIgnoreCase(record.getPrevHash())) {
                String msg = "Chain linkage broken at record #" + recordId + 
                             ": prev_hash mismatch. Expected [" + expectedPrevHash + 
                             "], found [" + record.getPrevHash() + "].";
                LOGGER.severe(msg);
                return VerificationResult.tampered(recordId, "PREV_HASH_MISMATCH", 
                        expectedPrevHash, record.getPrevHash(), msg);
            }

            // Step 2: Reconstruct exact canonical representation and verify record_hash
            String canonicalData = record.getCanonicalData();
            String computedHash = HashUtil.sha256(canonicalData + "|" + record.getPrevHash());

            if (!computedHash.equalsIgnoreCase(record.getRecordHash())) {
                String msg = "Tampering detected at record #" + recordId + 
                             ": content hash mismatch. Expected computed [" + computedHash + 
                             "], stored [" + record.getRecordHash() + "]. Record payload or metadata was altered!";
                LOGGER.severe(msg);
                return VerificationResult.tampered(recordId, "RECORD_HASH_MISMATCH", 
                        computedHash, record.getRecordHash(), msg);
            }

            // Advance expected previous hash for next link
            expectedPrevHash = record.getRecordHash();
        }

        String successMsg = "Audit chain verified intact. All " + records.size() + 
                           " records cryptographically validated against tampering.";
        LOGGER.info(successMsg);
        return VerificationResult.valid(records.size(), successMsg);
    }

    @Override
    public List<AuditRecord> getAuditTrail() {
        return auditLogDAO.findAllOrderedById();
    }

    @Override
    public int getRecordCount() {
        return auditLogDAO.count();
    }
}
