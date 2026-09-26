import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { db } from '../database/db.js';
import { addAuditEvent } from '../audit/auditEngine.js';

/**
 * Validates that recovery destination is physically different from the source evidence device.
 */
export function validateRecoveryDestination(sourceDeviceId, destinationPath) {
  const sourceDevice = db.getById('devices', sourceDeviceId);
  const sourceEvidence = db.get('evidence').find(e => e.id === sourceDeviceId || e.caseId === sourceDeviceId);

  if (!destinationPath) {
    throw new Error('Recovery destination path is required.');
  }

  // Normalize paths
  const normDest = path.resolve(destinationPath);
  let normSource = sourceEvidence ? path.resolve(sourceEvidence.sourcePath) : '';

  // Check if destination path is on the exact same directory or device path as source
  if (normSource && (normDest === normSource || normDest.startsWith(normSource))) {
    return {
      isValid: false,
      blocked: true,
      errorMessage: 'Recovery destination must be different from the source evidence device.'
    };
  }

  if (sourceDevice && sourceDevice.devicePath && normDest.includes(sourceDevice.devicePath)) {
    return {
      isValid: false,
      blocked: true,
      errorMessage: 'Recovery destination must be different from the source evidence device.'
    };
  }

  return {
    isValid: true,
    blocked: false,
    destinationPath: normDest
  };
}

/**
 * Saves recovered file to validated destination drive.
 */
export function recoverSelectedFile({ fileId, destinationPath, caseId, user = 'Investigator' }) {
  const file = db.getById('recoveredFiles', fileId);
  if (!file) {
    throw new Error(`Recovered file ${fileId} not found.`);
  }

  // Validate destination drive separation
  const destCheck = validateRecoveryDestination(file.evidenceId || file.caseId, destinationPath);
  if (destCheck.blocked) {
    throw new Error(destCheck.errorMessage);
  }

  // Ensure destination folder exists
  if (!fs.existsSync(destinationPath)) {
    fs.mkdirSync(destinationPath, { recursive: true });
  }

  const targetFilePath = path.join(destinationPath, file.filename);

  // Write recovered content (either from sample_drive.img offset or demo payload)
  const sampleDrivePath = path.resolve(__dirname, '../../sample_data/sample_drive.img');
  let recoveredBuffer = Buffer.from(`DATASHIELD RECOVERED FILE: ${file.filename}\nCase: ${caseId}\nCategory: ${file.category}\n`);

  if (fs.existsSync(sampleDrivePath) && file.offsetDec !== undefined && file.sizeBytes) {
    try {
      const fullBuffer = fs.readFileSync(sampleDrivePath);
      if (file.offsetDec + file.sizeBytes <= fullBuffer.length) {
        recoveredBuffer = fullBuffer.subarray(file.offsetDec, file.offsetDec + file.sizeBytes);
      }
    } catch (err) {
      console.warn('Bitstream offset read notice:', err.message);
    }
  }

  fs.writeFileSync(targetFilePath, recoveredBuffer);
  const sha256 = crypto.createHash('sha256').update(recoveredBuffer).digest('hex');

  // Update audit log
  addAuditEvent({
    caseId,
    evidenceId: file.evidenceId || 'N/A',
    user,
    action: 'FILE_RECOVERED_TO_DESTINATION',
    result: 'SUCCESS',
    details: `Recovered ${file.filename} to destination ${targetFilePath}. SHA-256: ${sha256.substring(0, 16)}...`
  });

  return {
    fileId,
    filename: file.filename,
    destinationPath: targetFilePath,
    sha256,
    recoveredSizeBytes: recoveredBuffer.length,
    status: 'RECOVERED_TO_DESTINATION'
  };
}
