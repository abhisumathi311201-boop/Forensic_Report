import crypto from 'crypto';
import { db } from '../database/db.js';

/**
 * Creates a tamper-evident audit event using SHA-256 cryptographic hash chaining.
 */
export function addAuditEvent({ caseId, evidenceId = 'N/A', user = 'Investigator', action, result = 'SUCCESS', details }) {
  const auditLogs = db.get('auditLogs');
  
  // Find previous event's hash, or genesis hash if empty
  const lastLog = auditLogs.length > 0 ? auditLogs[auditLogs.length - 1] : null;
  const prevHash = lastLog ? lastLog.hash : '0000000000000000000000000000000000000000000000000000000000000000';
  
  const id = `LOG-${String(auditLogs.length + 1).padStart(3, '0')}`;
  const timestamp = new Date().toISOString();
  
  // Format string for cryptographic hashing
  const rawContent = `${id}|${timestamp}|${user}|${caseId}|${action}|${details}|${prevHash}`;
  const hash = crypto.createHash('sha256').update(rawContent).digest('hex');

  const newLog = {
    id,
    timestamp,
    user,
    caseId,
    evidenceId,
    action,
    result,
    details,
    prevHash,
    hash
  };

  db.insert('auditLogs', newLog);
  return newLog;
}

/**
 * Verifies the integrity of the entire audit log chain.
 * Recomputes each hash from event data + previous hash.
 */
export function verifyAuditChain() {
  const auditLogs = db.get('auditLogs');
  if (auditLogs.length === 0) {
    return { isValid: true, totalEvents: 0, status: 'VERIFIED' };
  }

  let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  
  for (let i = 0; i < auditLogs.length; i++) {
    const log = auditLogs[i];

    // Check link to previous hash
    if (log.prevHash !== expectedPrevHash) {
      return {
        isValid: false,
        totalEvents: auditLogs.length,
        brokenAtStep: log.id,
        reason: `Previous hash mismatch at log item ${log.id}. Expected ${expectedPrevHash}, got ${log.prevHash}.`,
        status: 'TAMPER_DETECTED'
      };
    }

    // Re-calculate expected current hash
    const rawContent = `${log.id}|${log.timestamp}|${log.user}|${log.caseId}|${log.action}|${log.details}|${log.prevHash}`;
    const calculatedHash = crypto.createHash('sha256').update(rawContent).digest('hex');

    if (calculatedHash !== log.hash) {
      return {
        isValid: false,
        totalEvents: auditLogs.length,
        brokenAtStep: log.id,
        reason: `Hash tampered at log item ${log.id}. Stored: ${log.hash}, Calculated: ${calculatedHash}`,
        status: 'TAMPER_DETECTED'
      };
    }

    expectedPrevHash = log.hash;
  }

  return {
    isValid: true,
    totalEvents: auditLogs.length,
    status: 'VERIFIED'
  };
}
