import fs from 'fs';
import path from 'path';

const severityScore = {
  LOW: 8,
  MEDIUM: 25,
  HIGH: 60,
};

const addFinding = (findings, finding) => {
  findings.push(finding);
};

export const analyzeBuffer = ({ buffer, originalName, mimeType, size }) => {
  const findings = [];
  const extension = path.extname(originalName || '').toLowerCase();
  const lowerName = (originalName || '').toLowerCase();
  const header = buffer.subarray(0, 8192);
  const headerText = header.toString('latin1');
  const text = buffer.subarray(0, 1024 * 1024).toString('utf8');

  if (buffer.length === 0) {
    addFinding(findings, {
      code: 'EMPTY_FILE',
      severity: 'MEDIUM',
      title: 'Empty file',
      detail: 'The uploaded file contains no data.',
      recommendation: 'Confirm that the file was exported correctly before sharing it.',
    });
  }

  if (lowerName.match(/\.[a-z0-9]{1,8}\.[a-z0-9]{1,8}$/)) {
    addFinding(findings, {
      code: 'DOUBLE_EXTENSION',
      severity: 'MEDIUM',
      title: 'Double extension in filename',
      detail:
        'The filename contains multiple extensions, a pattern sometimes used to disguise executable files.',
      recommendation: 'Rename the file to a single, descriptive extension if this is expected.',
    });
  }

  if (
    header.subarray(0, 2).toString('ascii') === 'MZ' ||
    header.subarray(0, 4).toString('ascii') === '\x7fELF' ||
    header.subarray(0, 4).equals(Buffer.from([0xcf, 0xfa, 0xed, 0xfe]))
  ) {
    addFinding(findings, {
      code: 'EXECUTABLE_HEADER',
      severity: 'HIGH',
      title: 'Executable header detected',
      detail: 'The file begins with a Windows, Linux, or macOS executable signature.',
      recommendation:
        'Do not open or share this file unless you have verified its source through a trusted channel.',
    });
  }

  if (extension === '.pdf') {
    const pdfThreats = [
      [
        /JavaScript|\/JS/i,
        'PDF JavaScript',
        'JavaScript embedded in PDFs can be abused for phishing or malicious actions.',
      ],
      [
        /OpenAction|\/AA/i,
        'Automatic PDF action',
        'The PDF contains an action that may run when it is opened.',
      ],
      [
        /Launch|\/EmbeddedFile|\/RichMedia/i,
        'Embedded or launched content',
        'The PDF references embedded or launchable content.',
      ],
    ];

    for (const [pattern, title, detail] of pdfThreats) {
      if (pattern.test(headerText)) {
        addFinding(findings, {
          code: title.toUpperCase().replaceAll(' ', '_'),
          severity: title === 'PDF JavaScript' ? 'HIGH' : 'MEDIUM',
          title,
          detail,
          recommendation:
            'Open this PDF only in a patched viewer and verify the sender before enabling content.',
        });
      }
    }
  }

  if (
    mimeType === 'text/plain' &&
    /<script|javascript:|<iframe|onerror\s*=|powershell|cmd\.exe|<?php/i.test(text)
  ) {
    addFinding(findings, {
      code: 'ACTIVE_CONTENT_PATTERN',
      severity: 'HIGH',
      title: 'Active-content pattern detected',
      detail:
        'The text contains script or command patterns that may be unsafe when copied or executed.',
      recommendation: 'Treat the content as untrusted and do not execute commands copied from it.',
    });
  }

  if (size > 8 * 1024 * 1024) {
    addFinding(findings, {
      code: 'LARGE_FILE',
      severity: 'LOW',
      title: 'Large file',
      detail: 'Large files can increase scanning, storage, and download exposure.',
      recommendation: 'Confirm the file size and share it only with the intended recipients.',
    });
  }

  const riskScore = Math.min(
    100,
    findings.reduce((score, finding) => score + severityScore[finding.severity], 0),
  );

  return {
    status: findings.some((finding) => finding.severity === 'HIGH') ? 'REVIEW' : 'CLEAN',
    riskScore,
    findings,
    checkedAt: new Date(),
    engine: 'SecureShare header heuristics',
  };
};

export const analyzeFile = ({ filePath, originalName, mimeType, size }) =>
  analyzeBuffer({
    buffer: fs.readFileSync(filePath),
    originalName,
    mimeType,
    size,
  });
