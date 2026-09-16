package com.forensix.service;

/**
 * Encapsulates the outcome of a cryptographic audit hash-chain integrity verification.
 */
public class VerificationResult {
    private final boolean valid;
    private final int totalRecordsVerified;
    private final long brokenRecordId;
    private final String brokenField; // PREV_HASH_MISMATCH, RECORD_HASH_MISMATCH, NONE
    private final String expectedHash;
    private final String actualHash;
    private final String message;

    private VerificationResult(boolean valid, int totalRecordsVerified, long brokenRecordId,
                               String brokenField, String expectedHash, String actualHash, String message) {
        this.valid = valid;
        this.totalRecordsVerified = totalRecordsVerified;
        this.brokenRecordId = brokenRecordId;
        this.brokenField = brokenField;
        this.expectedHash = expectedHash;
        this.actualHash = actualHash;
        this.message = message;
    }

    public static VerificationResult valid(int totalRecordsVerified, String message) {
        return new VerificationResult(true, totalRecordsVerified, -1, "NONE", null, null, message);
    }

    public static VerificationResult tampered(long brokenRecordId, String brokenField,
                                             String expectedHash, String actualHash, String message) {
        return new VerificationResult(false, 0, brokenRecordId, brokenField, expectedHash, actualHash, message);
    }

    public boolean isValid() { return valid; }
    public int getTotalRecordsVerified() { return totalRecordsVerified; }
    public long getBrokenRecordId() { return brokenRecordId; }
    public String getBrokenField() { return brokenField; }
    public String getExpectedHash() { return expectedHash; }
    public String getActualHash() { return actualHash; }
    public String getMessage() { return message; }

    @Override
    public String toString() {
        if (valid) {
            return "VERIFIED [OK]: " + message;
        } else {
            return "TAMPERING DETECTED [ALERT]: Broken Record ID #" + brokenRecordId +
                    " (" + brokenField + ") - Expected: " + expectedHash + ", Found: " + actualHash;
        }
    }
}
