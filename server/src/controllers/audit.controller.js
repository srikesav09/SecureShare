import mongoose from 'mongoose';

import Audit from '../models/audit.model.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import { AUDIT_ACTIONS, AUDIT_STATUS } from '../utils/constants.js';
import { sanitizeAuditLog } from '../utils/auditSanitizer.js';

export const getMyAuditLogs = asyncHandler(async (req, res) => {
  const page = Number(req.query.page || 1);
  const limit = Number(req.query.limit || 30);

  if (!Number.isInteger(page) || page < 1 || !Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new AppError('Page must be positive and limit must be between 1 and 100', 400);
  }

  const userId = new mongoose.Types.ObjectId(req.user.id);
  const filter = {
    $or: [{ user: userId }, { 'details.ownerId': userId.toString() }],
  };

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

  const skip = (page - 1) * limit;
  const [logs, total] = await Promise.all([
    Audit.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Audit.countDocuments(filter),
  ]);

  return res.json({
    success: true,
    data: logs.map(sanitizeAuditLog),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});
