import { execSync } from 'child_process';
import os from 'os';
import { db } from '../database/db.js';

/**
 * Detects real physical connected storage hardware using OS commands (macOS diskutil / df / lsblk).
 */
export function detectRealHardwareDevices() {
  const detectedDevices = [];

  try {
    const platform = os.platform();

    if (platform === 'darwin') {
      // macOS real disk detection using diskutil
      const output = execSync('diskutil list', { encoding: 'utf8', timeout: 3000 });
      const lines = output.split('\n');
      let currentDisk = null;

      lines.forEach(line => {
        const diskMatch = line.match(/^(\/dev\/disk\d+)\s+\(([^)]+)\):/);
        if (diskMatch) {
          const devicePath = diskMatch[1];
          const diskTypeInfo = diskMatch[2]; // e.g. "external, physical", "internal, physical"
          const isRemovable = diskTypeInfo.includes('external') || diskTypeInfo.includes('removable');
          const isPhysical = diskTypeInfo.includes('physical');

          currentDisk = {
            id: `DEV-HW-${devicePath.replace('/dev/', '')}`,
            name: `Apple/Host Physical Drive (${devicePath})`,
            devicePath,
            type: isRemovable ? 'USB Flash / Removable Media' : 'NVMe / SSD (Internal System Drive)',
            capacity: 'Unknown',
            filesystem: 'APFS / HFS+ / FAT32',
            partitionInfo: diskTypeInfo,
            sectorSize: '512 / 4096 bytes',
            mountStatus: 'Mounted (Read-Only Mode)',
            readOnlyStatus: true,
            removable: isRemovable,
            isSystemDisk: !isRemovable,
            recommendedWorkflow: isRemovable 
              ? 'Sanitize: 2-Pass Zero-Fill + Random Overwrite' 
              : 'SYSTEM DISK PROTECTED - Data Sanitization Blocked'
          };

          // Try getting detailed capacity info for this disk
          try {
            const infoOut = execSync(`diskutil info ${devicePath}`, { encoding: 'utf8', timeout: 2000 });
            const sizeMatch = infoOut.match(/Disk Size:\s+([^\n]+)/);
            if (sizeMatch) {
              currentDisk.capacity = sizeMatch[1].split('(')[0].trim();
            }

            const nameMatch = infoOut.match(/Device \/ Media Name:\s+([^\n]+)/);
            if (nameMatch) {
              currentDisk.name = nameMatch[1].trim();
            }

            const fsMatch = infoOut.match(/File System Personality:\s+([^\n]+)/);
            if (fsMatch) {
              currentDisk.filesystem = fsMatch[1].trim();
            }
          } catch (e) {
            // Ignore sub-command errors
          }

          detectedDevices.push(currentDisk);
        }
      });
    } else if (platform === 'linux') {
      // Linux lsblk detection
      const output = execSync('lsblk -J -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT,RO,MODEL', { encoding: 'utf8', timeout: 3000 });
      const parsed = JSON.parse(output);
      if (parsed && parsed.blockdevices) {
        parsed.blockdevices.forEach(dev => {
          detectedDevices.push({
            id: `DEV-HW-${dev.name}`,
            name: dev.model || `Linux Storage Device (/dev/${dev.name})`,
            devicePath: `/dev/${dev.name}`,
            type: dev.type === 'disk' ? 'HDD / SSD' : 'Partition',
            capacity: dev.size,
            filesystem: dev.fstype || 'EXT4 / NTFS',
            partitionInfo: `Mount: ${dev.mountpoint || 'Unmounted'}`,
            sectorSize: '512 bytes',
            mountStatus: dev.mountpoint ? 'Mounted' : 'Unmounted',
            readOnlyStatus: Boolean(dev.ro),
            removable: dev.name.startsWith('sd') || dev.name.startsWith('mmc'),
            isSystemDisk: dev.mountpoint === '/',
            recommendedWorkflow: 'NIST 800-88 Standard Overwrite'
          });
        });
      }
    }
  } catch (err) {
    console.warn('[!] Real hardware detection OS command notice:', err.message);
  }

  // Merge detected real devices into database
  if (detectedDevices.length > 0) {
    detectedDevices.forEach(hwDev => {
      const existing = db.getById('devices', hwDev.id);
      if (!existing) {
        db.insert('devices', hwDev);
      } else {
        db.update('devices', hwDev.id, hwDev);
      }
    });
  }

  return detectedDevices;
}

/**
 * Device Analysis & Media Intelligence Engine
 */
export function analyzeDevice(deviceId) {
  // Trigger real hardware refresh first
  detectRealHardwareDevices();

  const device = db.getById('devices', deviceId);
  if (!device) {
    throw new Error(`Device ${deviceId} not found`);
  }

  let mediaIntelligence = {};

  if (device.isSystemDisk) {
    mediaIntelligence = {
      mediaClass: 'SYSTEM OPERATING SYSTEM DISK (PROTECTED)',
      recommendedSanitization: 'BLOCKED: System disk sanitization is prohibited to prevent OS destruction.',
      wearLevelingWarning: 'System disk contains active OS partitions and boot files.',
      forensicAcquisitionNote: 'Use live image acquisition or unmount volume before forensic analysis.'
    };
  } else {
    switch ((device.type || '').toUpperCase()) {
      case 'SSD':
      case 'NVME SSD':
      case 'NVME':
        mediaIntelligence = {
          mediaClass: 'Solid State Drive (NAND Flash)',
          recommendedSanitization: 'NIST 800-88 Purge: NVMe Format (Sanitize / Crypto Erase) + TRIM Command',
          wearLevelingWarning: 'Traditional multi-pass block overwriting is INEFFECTIVE on SSDs due to Wear-Leveling controller mappings. Use ATA/NVMe Sanitize firmware commands.',
          forensicAcquisitionNote: 'Use hardware write-blocker to prevent background TRIM/Garbage Collection from destroying unallocated space.'
        };
        break;

      case 'HDD':
        mediaIntelligence = {
          mediaClass: 'Magnetic Platter (HDD)',
          recommendedSanitization: 'NIST 800-88 Clear/Purge: DoD 5220.22-M 3-Pass Overwrite or Gutmann 35-Pass Algorithm',
          wearLevelingWarning: 'Magnetic platter supports direct sector overwrite. Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Random + Verification.',
          forensicAcquisitionNote: 'Direct bitstream imaging (dd / E01) recommended.'
        };
        break;

      default:
        mediaIntelligence = {
          mediaClass: 'Removable Storage Media (USB / SanDisk / SD Card)',
          recommendedSanitization: '2-Pass Overwrite (Zero-Fill + Pseudorandom Pattern)',
          wearLevelingWarning: 'Basic controller wear-leveling present. Overwrite entire user addressable logical block addresses (LBA).',
          forensicAcquisitionNote: 'Ensure physical write-protect switch is engaged if available.'
        };
    }
  }

  return {
    device,
    mediaIntelligence,
    analysisTime: new Date().toISOString()
  };
}
