import { execFile } from 'child_process';
import fs from 'fs';
import { promisify } from 'util';
import AppError from '../utils/AppError.js';

const execFileAsync = promisify(execFile);
const scanTimeoutMs = Number(process.env.CLAMAV_SCAN_TIMEOUT_MS || 30_000);

const required = process.env.CLAMAV_REQUIRED === 'true' || process.env.NODE_ENV === 'production';

const runScanner = async (command, filePath) => {
  try {
    const args = command.includes('clamdscan')
      ? ['--fdpass', '--no-summary', filePath]
      : ['--no-summary', filePath];

    await execFileAsync(command, args, {
      timeout: scanTimeoutMs,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });

    return { status: 'CLEAN', engine: command };
  } catch (error) {
    if (error.code === 1) {
      return {
        status: 'INFECTED',
        engine: command,
        signature: (error.stdout || error.stderr || '').trim().slice(0, 240),
      };
    }

    if (error.code === 'ENOENT') {
      return null;
    }

    return {
      status: 'ERROR',
      engine: command,
      reason: (error.stderr || error.message || 'Scanner failed').trim().slice(0, 240),
    };
  }
};

export const scanFileWithClamAV = async (filePath) => {
  const databaseDirectory = process.env.CLAMAV_DATABASE_DIR || '/var/lib/clamav';
  const hasDailyDatabase = ['daily.cvd', 'daily.cld'].some((name) =>
    fs.existsSync(`${databaseDirectory}/${name}`),
  );

  if (required && !hasDailyDatabase) {
    throw new AppError(
      'ClamAV signature database is incomplete. Uploads are temporarily disabled until freshclam completes.',
      503,
    );
  }

  const commands = [process.env.CLAMAV_DAEMON_COMMAND || 'clamdscan', 'clamscan'];
  let lastError = null;

  for (const command of commands) {
    const result = await runScanner(command, filePath);

    if (!result) continue;
    if (result.status === 'CLEAN' || result.status === 'INFECTED') return result;
    lastError = result;
  }

  if (required) {
    throw new AppError(
      `Malware scanner unavailable: ${lastError?.reason || 'install ClamAV and try again'}`,
      503,
    );
  }

  return {
    status: 'SKIPPED',
    engine: 'ClamAV not configured',
    reason: 'Set CLAMAV_REQUIRED=true after installing ClamAV.',
  };
};
