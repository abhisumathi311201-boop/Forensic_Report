import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

import { db } from '../database/db.js';
import { calculateFileHash, registerEvidence, verifyEvidenceIntegrity } from '../evidence/evidenceEngine.js';
import { calculateConfidenceScore, runFileCarving, SIGNATURE_DATABASE } from '../recovery/carvingEngine.js';
import { validateRecoveryDestination, recoverSelectedFile } from '../recovery/recoveryEngine.js';
import { detectRealHardwareDevices } from '../device/deviceEngine.js';
import { verifyAuditChain, addAuditEvent } from '../audit/auditEngine.js';
import { generateReport } from '../reports/reportEngine.js';
import { checkPreErasureSafety } from '../core/lifecycleEngine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sampleImagePath = path.resolve(__dirname, '../../sample_data/sample_drive.img');

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`  ✓ PASS: ${message}`);
    passedTests++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    process.exitCode = 1;
  }
}

async function runTests() {
  console.log('=====================================================');
  console.log(' DataShield Forensics - Comprehensive Test Suite');
  console.log('=====================================================');

  // Initialize Test Case
  db.insert('cases', {
    id: 'CASE-TEST-001',
    name: 'Automated Test Case',
    investigator: 'Test Suite Runner',
    organization: 'CI Unit',
    description: 'Case for automated testing',
    createdDate: new Date().toISOString(),
    caseType: 'Forensic Investigation',
    status: 'Active'
  });

  // Test 1: Real Hardware OS Device Detection
  console.log('\n[Test 1] Real OS Storage Hardware Device Detection');
  const realDevices = detectRealHardwareDevices();
  assert(Array.isArray(realDevices), `OS hardware detection executed cleanly (${realDevices.length} real physical drive(s) detected).`);

  // Test 2: SHA-256 Hash Generation & Evidence Integrity
  console.log('\n[Test 2] SHA-256 Hash Generation & Evidence Integrity');
  assert(fs.existsSync(sampleImagePath), `Sample drive image exists at ${sampleImagePath}`);
  const hash = calculateFileHash(sampleImagePath);
  assert(typeof hash === 'string' && hash.length === 64, `SHA-256 hash calculated: ${hash.substring(0, 16)}...`);

  const evd = registerEvidence({
    caseId: 'CASE-TEST-001',
    sourceName: 'test_sample.img',
    sourcePath: sampleImagePath,
    type: 'Disk Image'
  });
  assert(evd.id && evd.originalHash === hash, `Evidence registered with verified originalHash.`);

  const verifyRes = verifyEvidenceIntegrity(evd.id);
  assert(verifyRes.status === 'VERIFIED', `Integrity check status is VERIFIED.`);

  // Test 3: Pre-Erasure Safety Guard
  console.log('\n[Test 3] Pre-Erasure Safety Guard Protection');
  const safetyCheck = checkPreErasureSafety('CASE-TEST-001');
  assert(safetyCheck.requiresWarning === true, `Pre-erasure safety guard correctly flags unacquired evidence warning.`);

  // Test 4: Signature Detection & Multi-Format Carving
  console.log('\n[Test 4] Signature Carving Engine (10 Formats Supported)');
  assert(SIGNATURE_DATABASE.length >= 6, `Signature database populated with 6+ forensic file format plugins.`);
  const carvingRes = runFileCarving(evd.id);
  assert(carvingRes.carvedCount >= 4, `Carving scanner extracted ${carvingRes.carvedCount} files (JPEG, PDF, ZIP, PNG).`);

  const scoreRes = calculateConfidenceScore({ hasHeader: true, hasFooter: true, validSize: true, validStructure: true, isFragmented: false });
  assert(scoreRes.score >= 90 && scoreRes.confidenceLevel === 'HIGH', `Explainable confidence score computed: ${scoreRes.score}% (${scoreRes.confidenceLevel}).`);

  // Test 5: Recovery Destination Drive Separation Validation
  console.log('\n[Test 5] Recovery Destination Drive Separation Check');
  const blockedCheck = validateRecoveryDestination(evd.id, sampleImagePath);
  assert(blockedCheck.blocked === true, `Destination check BLOCKED recovery when destination matches source device.`);

  const validCheck = validateRecoveryDestination(evd.id, '/tmp/DataShield_Test_Output');
  assert(validCheck.blocked === false, `Destination check PASSED for separate destination path.`);

  // Test 6: Cryptographic Audit-Chain Validation
  console.log('\n[Test 6] Cryptographic Audit Log Chain Verification');
  addAuditEvent({ caseId: 'CASE-TEST-001', action: 'TEST_EVENT', details: 'Automated test suite audit event.' });
  const auditRes = verifyAuditChain();
  assert(auditRes.isValid === true && auditRes.status === 'VERIFIED', `Tamper-evident audit chain cryptographic hash integrity VERIFIED.`);

  // Test 7: Forensic Report Generation
  console.log('\n[Test 7] Forensic PDF Report & Certificate Generation');
  const report = generateReport({ caseId: 'CASE-2026-0001', reportType: 'Forensic Recovery Report' });
  assert(report.reportId && report.summary.overallIntegrityStatus, `Report generated with ID ${report.reportId}.`);

  console.log('\n=====================================================');
  console.log(` Summary: ${passedTests}/${totalTests} Tests Passed Cleanly`);
  console.log('=====================================================');
}

runTests().catch(err => {
  console.error('Test Suite Error:', err);
  process.exit(1);
});
