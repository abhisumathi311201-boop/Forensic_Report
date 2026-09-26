import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'datashield_db.json');

// Initial schema structure
const defaultData = {
  users: [
    { id: 'usr_1', username: 'admin', name: 'Dr. Rajesh Verma', role: 'Administrator', email: 'admin@datashield.gov.in', passwordHash: 'sha256_mock_hash' },
    { id: 'usr_2', username: 'investigator', name: 'Sgt. Vikram Singh', role: 'Investigator', email: 'v.singh@cyberforensics.gov.in', passwordHash: 'sha256_mock_hash' },
    { id: 'usr_3', username: 'viewer', name: 'Ananya Sharma', role: 'Viewer', email: 'a.sharma@cybercell.in', passwordHash: 'sha256_mock_hash' }
  ],
  cases: [
    {
      id: 'CASE-2026-0001',
      name: 'Cyber Heist Disk Forensic Investigation',
      investigator: 'Sgt. Vikram Singh',
      organization: 'Central Digital Forensics Lab (CDFL)',
      description: 'Acquisition and analysis of suspect media image sample_drive.img for financial breach evidence.',
      createdDate: '2026-09-24T09:30:00.000Z',
      caseType: 'Forensic Investigation', // Forensic Investigation | Data Sanitization | Combined
      status: 'Active'
    },
    {
      id: 'CASE-2026-0002',
      name: 'Departmental Storage Decommissioning',
      investigator: 'Dr. Rajesh Verma',
      organization: 'Defense Cyber Agency',
      description: 'NIST 800-88 Rev 1 compliant secure sanitization of decommissioned NVMe storage arrays.',
      createdDate: '2026-09-24T11:15:00.000Z',
      caseType: 'Data Sanitization',
      status: 'Active'
    }
  ],
  evidence: [
    {
      id: 'EVD-2026-0001',
      caseId: 'CASE-2026-0001',
      sourceName: 'sample_drive.img',
      sourcePath: path.resolve(__dirname, '../../sample_data/sample_drive.img'),
      type: 'Forensic Disk Image (.img)',
      sizeBytes: 2097152,
      originalHash: '8de9c0f89d96f06248e88b7cb7d96099aaddacfba16fab5f2d282b69f8c7a57c',
      currentHash: '8de9c0f89d96f06248e88b7cb7d96099aaddacfba16fab5f2d282b69f8c7a57c',
      integrityStatus: 'VERIFIED',
      addedTime: '2026-09-24T09:32:00.000Z',
      readOnly: true
    }
  ],
  devices: [
    {
      id: 'DEV-001',
      name: 'Seagate Barracuda ST1000LM048',
      type: 'HDD',
      capacity: '1.0 TB',
      capacityBytes: 1000204886016,
      filesystem: 'NTFS',
      partitionInfo: 'GPT - 2 Partitions (Primary Data, Recovery)',
      sectorSize: '512 bytes',
      mountStatus: 'Mounted (Read-Only)',
      readOnlyStatus: true,
      recommendedWorkflow: 'Multi-pass DoD 5220.22-M Overwrite (3 Passes)'
    },
    {
      id: 'DEV-002',
      name: 'Samsung 980 PRO PCIe 4.0 NVMe',
      type: 'NVMe SSD',
      capacity: '500 GB',
      capacityBytes: 500107862016,
      filesystem: 'EXT4',
      partitionInfo: 'GPT - 1 Partition',
      sectorSize: '4096 bytes',
      mountStatus: 'Unmounted',
      readOnlyStatus: false,
      recommendedWorkflow: 'NVMe Cryptographic Sanitize / Block Erase + TRIM Verification'
    },
    {
      id: 'DEV-003',
      name: 'SanDisk Ultra USB 3.0',
      type: 'USB Flash',
      capacity: '32 GB',
      capacityBytes: 32000000000,
      filesystem: 'FAT32',
      partitionInfo: 'MBR - 1 Partition',
      sectorSize: '512 bytes',
      mountStatus: 'Mounted',
      readOnlyStatus: false,
      recommendedWorkflow: 'Zero-Fill Overwrite + Random Pattern Pass'
    }
  ],
  operations: [
    {
      id: 'OP-1001',
      caseId: 'CASE-2026-0001',
      evidenceId: 'EVD-2026-0001',
      type: 'Forensic Acquisition & Carving',
      status: 'Completed',
      timestamp: '2026-09-24T09:35:00.000Z',
      user: 'Sgt. Vikram Singh',
      details: 'Extracted 4 carved files with signature matching.'
    }
  ],
  recoveredFiles: [
    {
      id: 'REC-001',
      caseId: 'CASE-2026-0001',
      evidenceId: 'EVD-2026-0001',
      filename: 'carved_evidence_photo_01.jpg',
      fileType: 'JPEG Image',
      category: 'Images',
      offsetHex: '0x00001000',
      offsetDec: 4096,
      sizeBytes: 138,
      confidenceScore: 96,
      confidenceLevel: 'HIGH',
      reconstructionStatus: 'Complete',
      reconstructionReasons: [
        '✓ Valid JPEG magic header (FF D8 FF E0)',
        '✓ Valid JPEG footer (FF D9)',
        '✓ Clean header-to-footer length boundary',
        '✓ Entropy continuity verified'
      ],
      recoveredAt: '2026-09-24T09:38:00.000Z'
    },
    {
      id: 'REC-002',
      caseId: 'CASE-2026-0001',
      evidenceId: 'EVD-2026-0001',
      filename: 'SIH_Forensic_Investigation_Report.pdf',
      fileType: 'PDF Document',
      category: 'Documents',
      offsetHex: '0x00008000',
      offsetDec: 32768,
      sizeBytes: 218,
      confidenceScore: 94,
      confidenceLevel: 'HIGH',
      reconstructionStatus: 'Complete',
      reconstructionReasons: [
        '✓ Valid PDF magic header (%PDF-1.7)',
        '✓ Valid PDF %%EOF trailer tag detected',
        '✓ Cross-reference table structure validated',
        '✓ No stream corruption detected'
      ],
      recoveredAt: '2026-09-24T09:39:00.000Z'
    },
    {
      id: 'REC-003',
      caseId: 'CASE-2026-0001',
      evidenceId: 'EVD-2026-0001',
      filename: 'suspect_evidence_logs.zip',
      fileType: 'ZIP Archive',
      category: 'Archives',
      offsetHex: '0x00018000',
      offsetDec: 98304,
      sizeBytes: 98,
      confidenceScore: 91,
      confidenceLevel: 'HIGH',
      reconstructionStatus: 'Complete',
      reconstructionReasons: [
        '✓ Valid ZIP Local File Header (50 4B 03 04)',
        '✓ Valid End of Central Directory signature (50 4B 05 06)',
        '✓ Central directory index verified'
      ],
      recoveredAt: '2026-09-24T09:40:00.000Z'
    },
    {
      id: 'REC-004',
      caseId: 'CASE-2026-0001',
      evidenceId: 'EVD-2026-0001',
      filename: 'intercepted_evidence_diagram.png',
      fileType: 'PNG Image',
      category: 'Images',
      offsetHex: '0x00030000',
      offsetDec: 196608,
      sizeBytes: 215,
      confidenceScore: 87,
      confidenceLevel: 'HIGH',
      reconstructionStatus: 'Reconstructed (3 Fragments)',
      fragmentCount: 3,
      missingFragments: 0,
      reconstructionReasons: [
        '✓ Valid PNG header chunk (89 50 4E 47)',
        '✓ Fragment 1 & 2 continuity sequence validated',
        '✓ Valid IEND footer chunk detected',
        '✓ Fragment reconstruction 100% complete'
      ],
      recoveredAt: '2026-09-24T09:42:00.000Z'
    }
  ],
  auditLogs: [],
  reports: [],
  verificationResults: [
    {
      id: 'VRF-001',
      caseId: 'CASE-2026-0001',
      evidenceIntegrity: 'VERIFIED',
      erasureVerification: 'NOT_APPLICABLE',
      recoveryValidation: 'VERIFIED',
      auditIntegrity: 'VERIFIED',
      overallStatus: 'VERIFIED',
      lastVerified: '2026-09-24T09:45:00.000Z'
    }
  ]
};

// Generate initial tamper-evident audit logs with cryptographic hash chaining
function initializeAuditLogs(data) {
  const genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
  let prevHash = genesisHash;

  const initialEvents = [
    { id: 'LOG-001', timestamp: '2026-09-24T09:30:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'N/A', action: 'CASE_CREATED', result: 'SUCCESS', details: 'Case CASE-2026-0001 initialized by Sgt. Vikram Singh.' },
    { id: 'LOG-002', timestamp: '2026-09-24T09:32:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'EVD-2026-0001', action: 'EVIDENCE_ADDED', result: 'SUCCESS', details: 'Evidence sample_drive.img registered with READ-ONLY lock.' },
    { id: 'LOG-003', timestamp: '2026-09-24T09:33:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'EVD-2026-0001', action: 'HASH_CREATED', result: 'SUCCESS', details: 'SHA-256 computed: 8de9c0f89d96f062... VERIFIED.' },
    { id: 'LOG-004', timestamp: '2026-09-24T09:35:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'EVD-2026-0001', action: 'DEVICE_ANALYZED', result: 'SUCCESS', details: 'Device structure analyzed: raw image, 2MB capacity.' },
    { id: 'LOG-005', timestamp: '2026-09-24T09:37:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'EVD-2026-0001', action: 'RECOVERY_STARTED', result: 'SUCCESS', details: 'Signature carving initiated with 6 active signature plugins.' },
    { id: 'LOG-006', timestamp: '2026-09-24T09:42:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'EVD-2026-0001', action: 'FILE_RECOVERED', result: 'SUCCESS', details: '4 evidence files recovered (JPG, PDF, ZIP, PNG) with avg confidence 92%.' },
    { id: 'LOG-007', timestamp: '2026-09-24T09:45:00.000Z', user: 'Sgt. Vikram Singh', caseId: 'CASE-2026-0001', evidenceId: 'EVD-2026-0001', action: 'VERIFICATION_COMPLETED', result: 'SUCCESS', details: 'Cryptographic hash and recovery structure verification passed.' }
  ];

  data.auditLogs = initialEvents.map(evt => {
    const rawContent = `${evt.id}|${evt.timestamp}|${evt.user}|${evt.caseId}|${evt.action}|${evt.details}|${prevHash}`;
    const hash = crypto.createHash('sha256').update(rawContent).digest('hex');
    const logItem = {
      ...evt,
      prevHash,
      hash
    };
    prevHash = hash;
    return logItem;
  });
}

class Database {
  constructor() {
    this.data = null;
    this.init();
  }

  init() {
    const dbDir = path.dirname(DB_FILE);
    if (!fs.existsSync(dbDir)) {
      try {
        fs.mkdirSync(dbDir, { recursive: true });
      } catch (err) {
        console.error('Failed to create DB directory:', err);
      }
    }
    if (!fs.existsSync(DB_FILE)) {
      this.data = JSON.parse(JSON.stringify(defaultData));
      initializeAuditLogs(this.data);
      this.save();
    } else {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        this.data = JSON.parse(raw);
        if (!this.data.auditLogs || this.data.auditLogs.length === 0) {
          initializeAuditLogs(this.data);
          this.save();
        }
      } catch (err) {
        console.error('Error reading DB, re-initializing:', err);
        this.data = JSON.parse(JSON.stringify(defaultData));
        initializeAuditLogs(this.data);
        this.save();
      }
    }
  }

  save() {
    fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2));
  }

  get(collection) {
    return this.data[collection] || [];
  }

  getById(collection, id) {
    return (this.data[collection] || []).find(item => item.id === id);
  }

  insert(collection, item) {
    if (!this.data[collection]) {
      this.data[collection] = [];
    }
    this.data[collection].push(item);
    this.save();
    return item;
  }

  update(collection, id, updates) {
    const list = this.data[collection] || [];
    const index = list.findIndex(item => item.id === id);
    if (index !== -1) {
      this.data[collection][index] = { ...list[index], ...updates };
      this.save();
      return this.data[collection][index];
    }
    return null;
  }

  delete(collection, id) {
    if (!this.data[collection]) return false;
    const initialLen = this.data[collection].length;
    this.data[collection] = this.data[collection].filter(item => item.id !== id);
    const deleted = this.data[collection].length < initialLen;
    if (deleted) this.save();
    return deleted;
  }
}

export const db = new Database();
