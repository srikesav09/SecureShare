import File from '../models/file.model.js';
import User from '../models/user.model.js';
import AppError from '../utils/AppError.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import mongoose from 'mongoose';

import {
  generateHash,
  encryptFile,
  generateHashFromBuffer,
  decryptBuffer,
} from './encryption.service.js';

import { createAuditLog } from './audit.service.js';

import { AUDIT_ACTIONS, AUDIT_STATUS, RESOURCE_TYPES } from '../utils/constants.js';

import { uploadToS3, downloadFromS3, deleteFromS3 } from './s3.service.js';
import { analyzeBuffer, analyzeFile } from './file-security.service.js';

const sanitizeFile = (file) => {
  if (!file) {
    return null;
  }

  const source = typeof file.toObject === 'function' ? file.toObject() : file;

  return {
    id: source._id,
    originalName: source.originalName,
    mimeType: source.mimeType,
    size: source.size,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
    securityAnalysis: source.securityAnalysis || null,
  };
};

export const saveFile = async (req, file, user) => {
  if (!file) {
    throw new AppError('No file uploaded', 400);
  }

  let encryption = null;
  let s3Key = null;
  let uploadedToS3 = false;

  try {
    const owner = await User.findById(user.id).select('storageUsed storageLimit');
    if (!owner) {
      throw new AppError('User not found', 404);
    }

    if (owner.storageUsed + file.size > owner.storageLimit) {
      throw new AppError('Storage limit exceeded', 413);
    }

    const hash = generateHash(file.path);

    const securityAnalysis = analyzeFile({
      filePath: file.path,
      originalName: file.originalname,
      mimeType: file.mimetype,
      size: file.size,
    });

    encryption = encryptFile(file.path);

    s3Key = `files/${user.id}/${file.filename}.enc`;

    const encryptedBuffer = fs.readFileSync(encryption.encryptedPath);

    await uploadToS3({
      key: s3Key,
      body: encryptedBuffer,
      contentType: 'application/octet-stream',
    });

    uploadedToS3 = true;

    const uploadedFile = await File.create({
      originalName: file.originalname,

      storedName: file.filename,

      mimeType: file.mimetype,

      size: file.size,

      s3Key,

      owner: user.id,

      iv: encryption.iv,

      hash,

      encrypted: true,

      securityAnalysis,
    });

    await User.updateOne({ _id: user.id }, { $inc: { storageUsed: file.size } });

    if (encryption.encryptedPath && fs.existsSync(encryption.encryptedPath)) {
      fs.unlinkSync(encryption.encryptedPath);
    }

    await createAuditLog({
      req,

      user: user.id,

      action: AUDIT_ACTIONS.UPLOAD_FILE,

      resourceType: RESOURCE_TYPES.FILE,

      resourceId: uploadedFile._id,

      status: AUDIT_STATUS.SUCCESS,

      details: {
        filename: uploadedFile.originalName,

        securityStatus: securityAnalysis.status,

        riskScore: securityAnalysis.riskScore,
      },
    });

    return {
      success: true,

      message: 'File uploaded successfully',

      data: sanitizeFile(uploadedFile),
    };
  } catch (error) {
    if (encryption?.encryptedPath && fs.existsSync(encryption.encryptedPath)) {
      try {
        fs.unlinkSync(encryption.encryptedPath);
      } catch (cleanupError) {
        console.error('Local cleanup failed:', cleanupError.message);
      }
    }

    if (uploadedToS3 && s3Key) {
      try {
        await deleteFromS3(s3Key);
      } catch (cleanupError) {
        console.error('S3 cleanup failed:', cleanupError.message);
      }
    }

    throw error;
  }
};

export const getFiles = async (userId) => {
  const files = await File.find({
    owner: userId,
  }).sort({
    createdAt: -1,
  });

  const safeFiles = files.map(sanitizeFile);

  return {
    success: true,

    message: 'Files fetched successfully',

    data: safeFiles,
  };
};

export const analyzeStoredFile = async (req, fileId, userId) => {
  if (!mongoose.Types.ObjectId.isValid(fileId)) {
    throw new AppError('Invalid file ID', 400);
  }

  const file = await File.findOne({ _id: fileId, owner: userId });
  if (!file) {
    throw new AppError('File not found', 404);
  }

  const encryptedBuffer = await downloadFromS3(file.s3Key);
  const decrypted = decryptBuffer(encryptedBuffer, file.iv);
  const currentHash = generateHashFromBuffer(decrypted);

  if (currentHash !== file.hash) {
    throw new AppError('Integrity check failed', 500);
  }

  const securityAnalysis = analyzeBuffer({
    buffer: decrypted,
    originalName: file.originalName,
    mimeType: file.mimeType,
    size: file.size,
  });

  await File.updateOne({ _id: file._id }, { $set: { securityAnalysis } });
  await createAuditLog({
    req,
    user: userId,
    action: AUDIT_ACTIONS.ANALYZE_FILE,
    resourceType: RESOURCE_TYPES.FILE,
    resourceId: file._id,
    status: AUDIT_STATUS.SUCCESS,
    details: { filename: file.originalName, securityStatus: securityAnalysis.status },
  });

  return { success: true, data: { ...sanitizeFile(file), securityAnalysis } };
};

export const importSharedFile = async (req, sharedFile, user) => {
  const temporaryPath = path.join('uploads', `shared-${crypto.randomUUID()}`);
  fs.writeFileSync(temporaryPath, sharedFile.buffer);

  try {
    return await saveFile(
      req,
      {
        path: temporaryPath,
        filename: path.basename(temporaryPath),
        originalname: sharedFile.metadata.originalName,
        mimetype: sharedFile.metadata.mimeType,
        size: sharedFile.buffer.length,
      },
      user,
    );
  } finally {
    if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
  }
};

export const downloadFileService = async (req, fileId, userId) => {
  if (!mongoose.Types.ObjectId.isValid(fileId)) {
    throw new AppError('Invalid file ID', 400);
  }

  const file = await File.findById(fileId);

  if (!file) {
    throw new AppError('File not found', 404);
  }

  if (file.owner.toString() !== userId.toString()) {
    throw new AppError('Access denied', 403);
  }

  let encryptedBuffer;

  try {
    encryptedBuffer = await downloadFromS3(file.s3Key);
  } catch (error) {
    console.error('S3 download failed:', error.message);

    throw new AppError('Unable to retrieve file from storage', 500);
  }

  const decrypted = decryptBuffer(encryptedBuffer, file.iv);

  const currentHash = generateHashFromBuffer(decrypted);

  if (currentHash !== file.hash) {
    throw new AppError('Integrity check failed', 500);
  }

  await createAuditLog({
    req,

    user: userId,

    action: req.query.preview === 'true' ? AUDIT_ACTIONS.PREVIEW_FILE : AUDIT_ACTIONS.DOWNLOAD_FILE,

    resourceType: RESOURCE_TYPES.FILE,

    resourceId: file._id,

    status: AUDIT_STATUS.SUCCESS,

    details: {
      filename: file.originalName,
    },
  });

  return {
    metadata: {
      originalName: file.originalName,

      mimeType: file.mimeType,
    },

    buffer: decrypted,
  };
};

export const deleteFileService = async (req, fileId, userId) => {
  if (!fileId) {
    throw new AppError('File ID is required', 400);
  }

  if (!mongoose.isValidObjectId(fileId)) {
    throw new AppError('Invalid file ID', 400);
  }

  const deletedFile = await File.findOneAndDelete({
    _id: fileId,

    owner: userId,
  });

  if (!deletedFile) {
    const existingFile = await File.exists({
      _id: fileId,
    });

    if (existingFile) {
      throw new AppError('You are not allowed to delete this file', 403);
    }

    throw new AppError('File not found', 404);
  }

  if (deletedFile.s3Key) {
    try {
      await deleteFromS3(deletedFile.s3Key);
    } catch (error) {
      console.error('S3 delete failed:', error.message);
    }
  }

  await User.updateOne({ _id: userId }, { $inc: { storageUsed: -deletedFile.size } });

  try {
    await createAuditLog({
      req,

      user: userId,

      action: AUDIT_ACTIONS.DELETE_FILE,

      resourceType: RESOURCE_TYPES.FILE,

      resourceId: deletedFile._id,

      status: AUDIT_STATUS.SUCCESS,

      details: {
        filename: deletedFile.originalName,
      },
    });
  } catch (error) {
    console.error('Delete audit logging failed:', error.message);
  }

  return {
    success: true,

    message: 'File deleted successfully',
  };
};
