import PDFDocument from 'pdfkit';
import { db } from '../database/db.js';
import { runFullVerification } from '../integrity/integrityEngine.js';

export function generateReport({ caseId, reportType = 'Forensic Recovery Report', format = 'JSON', user = 'Investigator' }) {
  const c = db.getById('cases', caseId) || { id: caseId, name: 'Forensic Case', investigator: user, organization: 'Cyber Unit' };
  const evidence = db.get('evidence').filter(e => e.caseId === caseId);
  const recoveredFiles = db.get('recoveredFiles').filter(r => r.caseId === caseId);
  const auditLogs = db.get('auditLogs').filter(l => l.caseId === caseId);
  const verification = runFullVerification(caseId);

  const reportId = `RPT-${Date.now()}`;
  const timestamp = new Date().toISOString();

  const reportData = {
    reportId,
    caseId: c.id,
    caseName: c.name,
    investigator: c.investigator,
    organization: c.organization,
    reportType,
    generatedAt: timestamp,
    summary: {
      totalEvidenceItems: evidence.length,
      totalRecoveredFiles: recoveredFiles.length,
      totalAuditEvents: auditLogs.length,
      overallIntegrityStatus: verification.overallStatus
    },
    evidenceList: evidence.map(e => ({ id: e.id, name: e.sourceName, hash: e.originalHash, status: e.integrityStatus })),
    recoveredFiles: recoveredFiles.map(r => ({ name: r.filename, type: r.fileType, offset: r.offsetHex, confidence: `${r.confidenceScore}% (${r.confidenceLevel})` })),
    auditTrailSummary: auditLogs.slice(-5).map(l => ({ id: l.id, time: l.timestamp, action: l.action, user: l.user, hash: l.hash.substring(0, 16) + '...' })),
    verificationResults: verification
  };

  db.insert('reports', {
    id: reportId,
    caseId,
    title: `${reportType} - Case ${caseId}`,
    type: reportType,
    format,
    generatedAt: timestamp,
    data: reportData
  });

  return reportData;
}

/**
 * Builds a clean PDF document buffer for a report.
 */
export function buildReportPDFBuffer(reportData) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50 });
      const buffers = [];

      doc.on('data', b => buffers.push(b));
      doc.on('end', () => resolve(Buffer.concat(buffers)));

      // Title & Header
      doc.fillColor('#0f172a').fontSize(22).text('DataShield Forensics', { align: 'left' });
      doc.fillColor('#64748b').fontSize(10).text('Secure Data Erasure & Advanced Digital Forensics Engine', { align: 'left' });
      doc.moveDown(0.5);

      doc.strokeColor('#cbd5e1').lineWidth(1).moveTo(50, doc.y).lineTo(550, doc.y).stroke();
      doc.moveDown(1);

      // Report Header Box
      doc.fillColor('#1e293b').fontSize(16).text(reportData.reportType.toUpperCase(), { align: 'center' });
      doc.moveDown(0.5);

      doc.fontSize(11).fillColor('#334155');
      doc.text(`Report ID: ${reportData.reportId}`);
      doc.text(`Case ID: ${reportData.caseId} - ${reportData.caseName}`);
      doc.text(`Investigator: ${reportData.investigator}`);
      doc.text(`Organization: ${reportData.organization}`);
      doc.text(`Generated Date: ${new Date(reportData.generatedAt).toLocaleString()}`);
      doc.moveDown(1);

      // System Verification Summary Box
      doc.fillColor('#0f172a').fontSize(13).text('EVIDENCE INTEGRITY & VERIFICATION SUMMARY', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor('#047857');
      doc.text(`Evidence Integrity Status: ${reportData.verificationResults.evidenceIntegrity}`);
      doc.text(`Recovery Validation Status: ${reportData.verificationResults.recoveryValidation}`);
      doc.text(`Cryptographic Audit Chain: ${reportData.verificationResults.auditIntegrity}`);
      doc.text(`Overall Case Verification: ${reportData.summary.overallIntegrityStatus}`);
      doc.moveDown(1);

      // Recovered Evidence Table
      doc.fillColor('#0f172a').fontSize(13).text('RECOVERED EVIDENCE FILES', { underline: true });
      doc.moveDown(0.5);

      if (reportData.recoveredFiles.length === 0) {
        doc.fontSize(10).fillColor('#64748b').text('No recovered files registered for this case.');
      } else {
        reportData.recoveredFiles.forEach((file, idx) => {
          doc.fontSize(10).fillColor('#1e293b').text(`${idx + 1}. ${file.name} | Type: ${file.type} | Offset: ${file.offset} | Confidence: ${file.confidence}`);
        });
      }

      doc.moveDown(1.5);

      // Cryptographic Audit Trail Snapshot
      doc.fillColor('#0f172a').fontSize(13).text('CRYPTOGRAPHIC AUDIT TRAIL (SHA-256 CHAIN)', { underline: true });
      doc.moveDown(0.5);

      reportData.auditTrailSummary.forEach((log) => {
        doc.fontSize(9).fillColor('#475569').text(`[${log.id}] ${log.time} - ${log.action} by ${log.user} (Hash: ${log.hash})`);
      });

      doc.moveDown(2);
      doc.fontSize(9).fillColor('#94a3b8').text('This report is digitally signed and cryptographically validated by DataShield Forensics Engine.', { align: 'center' });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
