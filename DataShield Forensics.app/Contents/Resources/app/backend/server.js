import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { db } from './database/db.js';
import { addAuditEvent, verifyAuditChain } from './audit/auditEngine.js';
import { evaluateCaseLifecycle, checkPreErasureSafety } from './core/lifecycleEngine.js';
import { registerEvidence, verifyEvidenceIntegrity, calculateFileHash } from './evidence/evidenceEngine.js';
import { analyzeDevice, detectRealHardwareDevices } from './device/deviceEngine.js';
import { runFileCarving, SIGNATURE_DATABASE } from './recovery/carvingEngine.js';
import { reconstructFragments } from './recovery/fragmentEngine.js';
import { validateRecoveryDestination, recoverSelectedFile } from './recovery/recoveryEngine.js';
import { executeDriveErasure, executeFileErasure, SANITIZATION_METHODS } from './erasure/erasureEngine.js';
import { runFullVerification } from './integrity/integrityEngine.js';
import { generateReport, buildReportPDFBuffer } from './reports/reportEngine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());

const SANDBOX_DIR = path.resolve(__dirname, '../sample_data/sandbox');

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    application: 'DataShield Forensics Backend',
    version: '1.0.0-SIH2026',
    timestamp: new Date().toISOString()
  });
});

// System status & health
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ONLINE',
    application: 'DataShield Forensics',
    version: '1.0.0-SIH2026',
    safeDemoMode: true,
    lifecycleEngine: 'Evidence-Aware Intelligent Data Lifecycle Engine ACTIVE',
    database: 'SQLite DB Connected',
    totalCases: db.get('cases').length,
    activeEvidence: db.get('evidence').length,
    timestamp: new Date().toISOString()
  });
});

// CASES API
app.get('/api/cases', (req, res) => {
  res.json(db.get('cases'));
});

app.get('/api/cases/:id', (req, res) => {
  const c = db.getById('cases', req.params.id);
  if (!c) return res.status(404).json({ error: 'Case not found' });

  const evidence = db.get('evidence').filter(e => e.caseId === c.id);
  const recoveredFiles = db.get('recoveredFiles').filter(r => r.caseId === c.id);
  const auditLogs = db.get('auditLogs').filter(l => l.caseId === c.id);
  const lifecycle = evaluateCaseLifecycle(c.id);

  res.json({
    case: c,
    evidence,
    recoveredFiles,
    auditLogs,
    lifecycle
  });
});

app.post('/api/cases', (req, res) => {
  const { name, investigator, organization, description, caseType } = req.body;
  if (!name || !caseType) {
    return res.status(400).json({ error: 'Case name and caseType are required.' });
  }

  const caseCount = db.get('cases').length + 1;
  const caseId = `CASE-2026-${String(caseCount).padStart(4, '0')}`;
  const now = new Date().toISOString();

  const newCase = {
    id: caseId,
    name,
    investigator: investigator || 'Investigator S. Sharma',
    organization: organization || 'Central Digital Forensics Lab (CDFL)',
    description: description || 'Digital evidence investigation and sanitization case.',
    createdDate: now,
    caseType,
    status: 'Active'
  };

  db.insert('cases', newCase);

  addAuditEvent({
    caseId,
    user: newCase.investigator,
    action: 'CASE_CREATED',
    result: 'SUCCESS',
    details: `Case ${caseId} (${name}) created under category ${caseType}.`
  });

  res.status(201).json(newCase);
});

// EVIDENCE API
app.get('/api/evidence', (req, res) => {
  const { caseId } = req.query;
  const list = db.get('evidence');
  if (caseId) {
    return res.json(list.filter(e => e.caseId === caseId));
  }
  res.json(list);
});

app.post('/api/evidence', (req, res) => {
  const { caseId, sourceName, sourcePath, type, user } = req.body;
  if (!caseId || !sourceName) {
    return res.status(400).json({ error: 'caseId and sourceName are required.' });
  }

  const defaultPath = sourcePath || path.resolve(__dirname, '../sample_data/sample_drive.img');
  
  try {
    const item = registerEvidence({
      caseId,
      sourceName,
      sourcePath: defaultPath,
      type: type || 'Forensic Disk Image (.img)',
      user: user || 'Investigator'
    });
    res.status(201).json(item);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/evidence/:id/verify', (req, res) => {
  try {
    const result = verifyEvidenceIntegrity(req.params.id, req.body.user || 'Investigator');
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DEVICES API (with Real OS Hardware Detection!)
app.get('/api/devices', (req, res) => {
  detectRealHardwareDevices();
  res.json(db.get('devices'));
});

app.get('/api/devices/detect', (req, res) => {
  const realDevices = detectRealHardwareDevices();
  res.json({
    realDeviceCount: realDevices.length,
    devices: db.get('devices')
  });
});

app.get('/api/devices/:id/analyze', (req, res) => {
  try {
    const analysis = analyzeDevice(req.params.id);
    res.json(analysis);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// RECOVERY & CARVING API
app.get('/api/recovery/signatures', (req, res) => {
  res.json(SIGNATURE_DATABASE);
});

app.get('/api/recovery/files', (req, res) => {
  const { caseId } = req.query;
  const files = db.get('recoveredFiles');
  if (caseId) {
    return res.json(files.filter(r => r.caseId === caseId));
  }
  res.json(files);
});

app.post('/api/recovery/carve', (req, res) => {
  const { evidenceId, user } = req.body;
  if (!evidenceId) {
    return res.status(400).json({ error: 'evidenceId is required' });
  }

  try {
    const result = runFileCarving(evidenceId, user || 'Investigator');
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/recovery/validate-destination', (req, res) => {
  const { sourceDeviceId, destinationPath } = req.body;
  try {
    const check = validateRecoveryDestination(sourceDeviceId, destinationPath);
    res.json(check);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/recovery/restore', (req, res) => {
  const { fileId, destinationPath, caseId, user } = req.body;
  if (!fileId || !destinationPath || !caseId) {
    return res.status(400).json({ error: 'fileId, destinationPath, and caseId are required.' });
  }

  try {
    const result = recoverSelectedFile({ fileId, destinationPath, caseId, user });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/recovery/reconstruct', (req, res) => {
  const { caseId, evidenceId, fragmentMap, targetFilename } = req.body;
  try {
    const result = reconstructFragments({ caseId, evidenceId, fragmentMap, targetFilename });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ERASURE & PRE-SAFETY GUARD API
app.get('/api/erasure/methods', (req, res) => {
  res.json(SANITIZATION_METHODS);
});

app.get('/api/erasure/pre-check', (req, res) => {
  const { caseId, targetDeviceId, targetEvidenceId } = req.query;
  if (!caseId) {
    return res.status(400).json({ error: 'caseId parameter required' });
  }

  try {
    const check = checkPreErasureSafety(caseId, targetDeviceId, targetEvidenceId);
    res.json(check);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/erasure/drive', (req, res) => {
  const { caseId, deviceId, methodId, confirmationPhrase, user, safeDemoMode } = req.body;
  if (!caseId || !deviceId || !confirmationPhrase) {
    return res.status(400).json({ error: 'caseId, deviceId, and confirmationPhrase are required.' });
  }

  try {
    const cert = executeDriveErasure({
      caseId,
      deviceId,
      methodId,
      confirmationPhrase,
      user,
      safeDemoMode: safeDemoMode !== undefined ? safeDemoMode : true
    });
    res.json(cert);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/sandbox/files', (req, res) => {
  try {
    if (!fs.existsSync(SANDBOX_DIR)) {
      return res.json([]);
    }
    const files = fs.readdirSync(SANDBOX_DIR).map(filename => {
      const fullPath = path.join(SANDBOX_DIR, filename);
      const stats = fs.statSync(fullPath);
      const hash = calculateFileHash(fullPath);
      return {
        filename,
        path: fullPath,
        sizeBytes: stats.size,
        modifiedDate: stats.mtime,
        hash
      };
    });
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/erasure/files', (req, res) => {
  const { caseId, filePaths, methodId, user } = req.body;
  if (!caseId || !filePaths || filePaths.length === 0) {
    return res.status(400).json({ error: 'caseId and filePaths array required.' });
  }

  try {
    const result = executeFileErasure({ caseId, filePaths, methodId, user });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VERIFICATION CENTER API
app.get('/api/verification', (req, res) => {
  const { caseId } = req.query;
  try {
    const result = runFullVerification(caseId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// AUDIT LOGS API
app.get('/api/audit', (req, res) => {
  const { caseId } = req.query;
  const logs = db.get('auditLogs');
  if (caseId) {
    return res.json(logs.filter(l => l.caseId === caseId));
  }
  res.json(logs);
});

app.get('/api/audit/verify', (req, res) => {
  const check = verifyAuditChain();
  res.json(check);
});

// REPORTS API
app.get('/api/reports', (req, res) => {
  const { caseId } = req.query;
  const list = db.get('reports');
  if (caseId) {
    return res.json(list.filter(r => r.caseId === caseId));
  }
  res.json(list);
});

app.post('/api/reports/generate', (req, res) => {
  const { caseId, reportType, format, user } = req.body;
  if (!caseId) {
    return res.status(400).json({ error: 'caseId is required' });
  }

  try {
    const rpt = generateReport({ caseId, reportType, format, user });
    res.json(rpt);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/reports/:id/pdf', async (req, res) => {
  const rpt = db.getById('reports', req.params.id);
  if (!rpt) {
    return res.status(404).json({ error: 'Report not found' });
  }

  try {
    const pdfBuffer = await buildReportPDFBuffer(rpt.data);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${rpt.id}_Report.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Static Production Frontend File Serving
const FRONTEND_DIST = process.env.FRONTEND_DIST || path.resolve(__dirname, '../frontend/dist');
if (fs.existsSync(FRONTEND_DIST)) {
  console.log(`[+] Serving production frontend static bundle from ${FRONTEND_DIST}`);
  app.use(express.static(FRONTEND_DIST));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path === '/health') return next();
    res.sendFile(path.join(FRONTEND_DIST, 'index.html'));
  });
} else {
  console.error(`[!] WARNING: Frontend dist static directory not found at ${FRONTEND_DIST}`);
}

// Global Error Handler Middleware
app.use((err, req, res, next) => {
  console.error('[!] Global API Error:', err.stack);
  res.status(500).json({
    error: err.message || 'Internal Server Error',
    path: req.path
  });
});

if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[+] DataShield Forensics Backend Server running on http://localhost:${PORT}`);
    console.log(`[+] Real OS Hardware Detection: ENABLED`);
    console.log(`[+] Safe Demo Mode: ENABLED`);
  });
}

export default app;

