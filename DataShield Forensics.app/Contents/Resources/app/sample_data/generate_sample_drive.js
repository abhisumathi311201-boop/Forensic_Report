import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SAMPLE_DIR = __dirname;
const SANDBOX_DIR = path.join(SAMPLE_DIR, 'sandbox');

if (!fs.existsSync(SANDBOX_DIR)) {
  fs.mkdirSync(SANDBOX_DIR, { recursive: true });
}

// 1. Generate Sample Sandbox Files for File & Folder Eraser
const file1 = path.join(SANDBOX_DIR, 'classified_evidence_log.txt');
const file2 = path.join(SANDBOX_DIR, 'suspect_financials.csv');
const file3 = path.join(SANDBOX_DIR, 'system_dump.log');

fs.writeFileSync(file1, 'CONFIDENTIAL FORENSIC LOG: Suspect activity logged on 2026-09-24 at 14:32 UTC.');
fs.writeFileSync(file2, 'TransactionID,Sender,Receiver,Amount,Status\nTX1001,UserA,UserB,50000,COMPLETED\nTX1002,UserC,UserD,120000,PENDING\n');
fs.writeFileSync(file3, '[DEBUG] System boot sequence started...\n[INFO] Interface eth0 up\n[WARN] Security alert triggered at sector 0x400\n');

// 2. Generate sample_drive.img with binary signatures
// Total size: 2MB (2 * 1024 * 1024 bytes)
const driveBuffer = Buffer.alloc(2 * 1024 * 1024);

// Fill with some dummy noise/zeroes
driveBuffer.fill(0x00);

// Helper to write string / hex at offset
function writeAtOffset(offset, hexStr) {
  const bytes = Buffer.from(hexStr.replace(/\s+/g, ''), 'hex');
  bytes.copy(driveBuffer, offset);
}

function writeBufferAtOffset(offset, buf) {
  buf.copy(driveBuffer, offset);
}

// --- ITEM 1: JPEG Image at offset 0x1000 (4096) ---
// JPEG Header: FF D8 FF E0 00 10 4A 46 49 46 00 01
// JPEG Footer: FF D9
const jpgHeader = 'ffd8ffe000104a46494600010101006000600000';
const jpgPayload = Buffer.from('DATASHIELD_FORENSIC_ACQUISITION_JPEG_PAYLOAD_SAMPLE_PHOTO_RECOVERED_SUCCESSFULLY_CASE_2026_0001');
const jpgFooter = 'ffd9';
writeAtOffset(0x1000, jpgHeader);
writeBufferAtOffset(0x1000 + 20, jpgPayload);
writeAtOffset(0x1000 + 20 + jpgPayload.length, jpgFooter);

// --- ITEM 2: PDF Document at offset 0x8000 (32768) ---
// PDF Header: 25 50 44 46 ( %PDF-1.7 )
// PDF Footer: 25 25 45 4F 46 ( %%EOF )
const pdfHeader = Buffer.from('%PDF-1.7\n%Digital Forensics Report\n1 0 obj\n<< /Title (Smart India Hackathon 2026 Forensic Case) /Author (Investigator S. Sharma) >>\nendobj\n');
const pdfFooter = Buffer.from('\n%%EOF\n');
writeBufferAtOffset(0x8000, pdfHeader);
writeBufferAtOffset(0x8000 + pdfHeader.length + 100, pdfFooter);

// --- ITEM 3: ZIP Archive at offset 0x18000 (98304) ---
// ZIP Header: 50 4B 03 04
// ZIP End of Central Dir: 50 4B 05 06
const zipHeader = '504b0304140000000800';
const zipPayload = Buffer.from('ZIP_ARCHIVE_CONTAINING_EVIDENCE_LOGS_2026_CASE');
const zipEocd = '504b05060000000001000100380000004f0000000000';
writeAtOffset(0x18000, zipHeader);
writeBufferAtOffset(0x18000 + 10, zipPayload);
writeAtOffset(0x18000 + 10 + zipPayload.length, zipEocd);

// --- ITEM 4: PNG Image (Fragmented!) ---
// PNG Header: 89 50 4E 47 0D 0A 1A 0A
// Fragment 1 at offset 0x30000 (196608)
// Fragment 2 at offset 0x38000 (229376)
// Fragment 3 at offset 0x40000 (262144) - PNG IEND Footer: 49 45 4E 44 AE 42 60 82
const pngHeader = '89504e470d0a1a0a0000000d4948445200000100000001000806000000';
const pngFrag1 = Buffer.from('PNG_FRAGMENT_1_IMAGE_DATA_HEADER_CHUNK_PASSED_INTEGRITY_CHECK_');
const pngFrag2 = Buffer.from('PNG_FRAGMENT_2_IMAGE_DATA_BODY_CHUNK_CONTINUITY_VERIFIED_SCORE_HIGH_');
const pngFrag3Header = Buffer.from('PNG_FRAGMENT_3_FINAL_CHUNK_');
const pngFooter = '49454e44ae426082';

writeAtOffset(0x30000, pngHeader);
writeBufferAtOffset(0x30000 + 28, pngFrag1);

writeBufferAtOffset(0x38000, pngFrag2);

writeBufferAtOffset(0x40000, pngFrag3Header);
writeAtOffset(0x40000 + pngFrag3Header.length, pngFooter);

// Write sample_drive.img file
const imagePath = path.join(SAMPLE_DIR, 'sample_drive.img');
fs.writeFileSync(imagePath, driveBuffer);

const imageHash = crypto.createHash('sha256').update(driveBuffer).digest('hex');

console.log(`[+] Sample Drive Image Created: ${imagePath}`);
console.log(`[+] Size: ${driveBuffer.length} bytes (2.0 MB)`);
console.log(`[+] SHA-256 Hash: ${imageHash}`);
console.log(`[+] Embedded Signatures: JPEG @ 0x1000, PDF @ 0x8000, ZIP @ 0x18000, PNG (Fragmented 3-part) @ 0x30000`);
