import mongoose from 'mongoose';

import { asyncHandler } from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import Audit from '../models/audit.model.js';
import User from '../models/user.model.js';
import File from '../models/file.model.js';
import { getQuarantinedFiles, releaseQuarantinedFile } from '../services/file.service.js';

import { AUDIT_ACTIONS, AUDIT_STATUS } from '../utils/constants.js';

import { sanitizeAuditLog } from '../utils/auditSanitizer.js';

export const getAuditLogs = asyncHandler(async (req, res) => {
  const pageValue = Number(req.query.page || 1);

  const limitValue = Number(req.query.limit || 20);

  if (!Number.isInteger(pageValue) || pageValue < 1) {
    throw new AppError('Page must be a positive integer', 400);
  }

  if (!Number.isInteger(limitValue) || limitValue < 1 || limitValue > 100) {
    throw new AppError('Limit must be between 1 and 100', 400);
  }

  const page = pageValue;
  const limit = limitValue;

  const skip = (page - 1) * limit;

  const filter = {};

  if (req.query.status) {
    if (!Object.values(AUDIT_STATUS).includes(req.query.status)) {
      throw new AppError('Invalid audit status', 400);
    }

    filter.status = req.query.status;
  }

  if (req.query.action) {
    if (!Object.values(AUDIT_ACTIONS).includes(req.query.action)) {
      throw new AppError('Invalid audit action', 400);
    }

    filter.action = req.query.action;
  }

  if (req.query.user) {
    if (!mongoose.Types.ObjectId.isValid(req.query.user)) {
      throw new AppError('Invalid user ID', 400);
    }

    filter.user = req.query.user;
  }

  const [logs, total] = await Promise.all([
    Audit.find(filter)
      .populate('user', 'name email role')
      .sort({
        createdAt: -1,
      })
      .skip(skip)
      .limit(limit)
      .lean(),

    Audit.countDocuments(filter),
  ]);

  return res.status(200).json({
    success: true,

    data: logs.map(sanitizeAuditLog),

    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
    },
  });
});

export const getDashboard = asyncHandler(async (req, res) => {
  const [users, files, quarantined, recentLogs] = await Promise.all([
    User.countDocuments(),
    File.countDocuments(),
    File.countDocuments({ 'securityAnalysis.status': 'QUARANTINED' }),
    Audit.find().populate('user', 'name email role').sort({ createdAt: -1 }).limit(12).lean(),
  ]);

  return res.status(200).json({
    success: true,
    data: {
      metrics: { users, files, quarantined },
      recentLogs: recentLogs.map(sanitizeAuditLog),
    },
  });
});

export const getQuarantineQueue = asyncHandler(async (req, res) => {
  return res.status(200).json({ success: true, data: await getQuarantinedFiles() });
});

export const releaseQuarantined = asyncHandler(async (req, res) => {
  return res.status(200).json(await releaseQuarantinedFile(req, req.params.fileId, req.user.id));
});
