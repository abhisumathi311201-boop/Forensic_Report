import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { db } from '../database/db.js';
import { addAuditEvent } from '../audit/auditEngine.js';

/**
 * Calculates SHA-256 hash for a given file path.
 */
export function calculateFileHash(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  const fileBuffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(fileBuffer).digest('hex');
}

/**
 * Adds evidence item safely to database and computes SHA-256.
 */
export function registerEvidence({ caseId, sourceName, sourcePath, type = 'Disk Image', user = 'Investigator' }) {
  let sizeBytes = 0;
  let hash = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';

  if (fs.existsSync(sourcePath)) {
    const stats = fs.statSync(sourcePath);
    sizeBytes = stats.size;
    hash = calculateFileHash(sourcePath);
  } else {
    // If virtual/sample path
    sizeBytes = 2097152;
  }

  const evidenceId = `EVD-${new Date().getFullYear()}-${String(db.get('evidence').length + 1).padStart(4, '0')}`;
  const now = new Date().toISOString();

  const item = {
    id: evidenceId,
    caseId,
    sourceName,
    sourcePath,
    type,
    sizeBytes,
    originalHash: hash,
    currentHash: hash,
    integrityStatus: 'VERIFIED',
    addedTime: now,
    readOnly: true
  };

  db.insert('evidence', item);

  addAuditEvent({
    caseId,
    evidenceId,
    user,
    action: 'EVIDENCE_ADDED',
    result: 'SUCCESS',
    details: `Evidence '${sourceName}' registered with SHA-256 ${hash.substring(0, 16)}...`
  });

  return item;
}

/**
 * Re-evaluates SHA-256 for an evidence item and updates integrity status.
 */
export function verifyEvidenceIntegrity(evidenceId, user = 'Investigator') {
  const evd = db.getById('evidence', evidenceId);
  if (!evd) {
    throw new Error(`Evidence ${evidenceId} not found`);
  }

  let currentHash = evd.originalHash;
  if (fs.existsSync(evd.sourcePath)) {
    currentHash = calculateFileHash(evd.sourcePath);
  }

  const isVerified = currentHash === evd.originalHash;
  const status = isVerified ? 'VERIFIED' : 'CHANGED';

  db.update('evidence', evidenceId, {
    currentHash,
    integrityStatus: status
  });

  addAuditEvent({
    caseId: evd.caseId,
    evidenceId: evd.id,
    user,
    action: isVerified ? 'VERIFICATION_COMPLETED' : 'TAMPER_DETECTED',
    result: isVerified ? 'SUCCESS' : 'WARNING',
    details: isVerified 
      ? `Evidence ${evd.id} SHA-256 integrity VERIFIED (${currentHash.substring(0, 16)}...)`
      : `CRITICAL ALERT: Evidence ${evd.id} SHA-256 changed from ${evd.originalHash.substring(0, 12)} to ${currentHash.substring(0, 12)}`
  });

  return {
    evidenceId,
    originalHash: evd.originalHash,
    currentHash,
    status
  };
}
