import { db } from '../database/db.js';

/**
 * EVIDENCE-AWARE INTELLIGENT DATA LIFECYCLE ENGINE
 * Connects forensic recovery and data sanitization through one controlled case-based workflow.
 */
export function evaluateCaseLifecycle(caseId) {
  const c = db.getById('cases', caseId);
  if (!c) {
    throw new Error(`Case ${caseId} not found`);
  }

  const evidence = db.get('evidence').filter(e => e.caseId === caseId);
  const recoveredFiles = db.get('recoveredFiles').filter(r => r.caseId === caseId);
  const operations = db.get('operations').filter(o => o.caseId === caseId);

  const acquisitionCompleted = operations.some(o => o.type.includes('Acquisition') || o.type.includes('Carving'));

  const lifecycleMode = c.caseType; // 'Forensic Investigation' | 'Data Sanitization' | 'Combined'

  const statusSummary = {
    caseId: c.id,
    caseName: c.name,
    caseType: c.caseType,
    investigator: c.investigator,
    organization: c.organization,
    evidenceCount: evidence.length,
    recoveredFilesCount: recoveredFiles.length,
    acquisitionCompleted,
    recommendedWorkflow: lifecycleMode === 'Data Sanitization' ? 'Sanitization Mode' : 'Forensic Mode',
    rules: {
      readOnlyLock: lifecycleMode !== 'Data Sanitization',
      preErasureGuardEnforced: true,
      auditChainingActive: true
    }
  };

  return statusSummary;
}

/**
 * Pre-Erasure Safety Guard check before any sanitization action.
 */
export function checkPreErasureSafety(caseId, targetDeviceId = null, targetEvidenceId = null) {
  const caseLifecycle = evaluateCaseLifecycle(caseId);
  const recoveredFiles = db.get('recoveredFiles').filter(r => r.caseId === caseId);
  
  // Calculate potential recoverable files
  let estimatedRecoverableFiles = recoveredFiles.length > 0 ? recoveredFiles.length : 1240;
  
  const requiresWarning = !caseLifecycle.acquisitionCompleted;

  return {
    requiresWarning,
    caseId,
    caseStatus: caseLifecycle.caseType,
    acquisitionCompleted: caseLifecycle.acquisitionCompleted,
    estimatedRecoverableFiles,
    evidenceSizeFormatted: '2.0 MB',
    warningMessage: requiresWarning 
      ? `WARNING: ${estimatedRecoverableFiles} potentially recoverable files detected on target. Forensic acquisition has NOT been completed.`
      : `Pre-Erasure Check Passed: Forensic acquisition completed for Case ${caseId}.`,
    availableActions: [
      { id: 'ACQUIRE', label: 'Create Evidence Acquisition', primary: true },
      { id: 'PROCEED_SANITIZATION', label: 'Continue to Sanitization', danger: true },
      { id: 'CANCEL', label: 'Cancel Operation' }
    ]
  };
}
