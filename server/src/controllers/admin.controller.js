import mongoose from 'mongoose';

import { asyncHandler } from '../utils/asyncHandler.js';
import AppError from '../utils/AppError.js';
import Audit from '../models/audit.model.js';
import User from '../models/user.model.js';
import File from '../models/file.model.js';

import { createAuditLog } from '../services/audit.service.js';
import { AUDIT_ACTIONS, AUDIT_STATUS, RESOURCE_TYPES } from '../utils/constants.js';

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
  const [users, blockedUsers, files, failedEvents, recentLogs] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ isBlocked: true }),
    File.countDocuments(),
    Audit.countDocuments({ status: AUDIT_STATUS.FAILED }),
    Audit.find().populate('user', 'name email role').sort({ createdAt: -1 }).limit(12).lean(),
  ]);

  return res.status(200).json({
    success: true,
    data: {
      metrics: { users, blockedUsers, files, failedEvents },
      recentLogs: recentLogs.map(sanitizeAuditLog),
    },
  });
});

export const listUsers = asyncHandler(async (req, res) => {
  const users = await User.find()
    .select('name email role isBlocked storageUsed storageLimit createdAt')
    .sort({ createdAt: -1 })
    .limit(100)
    .lean();

  const usersWithActivity = await Promise.all(
    users.map(async ({ _id, ...user }) => {
      const recentLogs = await Audit.find({ user: _id }).sort({ createdAt: -1 }).limit(5).lean();

      return {
        id: _id,
        ...user,
        recentLogs: recentLogs.map(sanitizeAuditLog),
      };
    }),
  );

  return res.status(200).json({
    success: true,
    data: usersWithActivity,
  });
});

export const setUserBlocked = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { blocked } = req.body;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    throw new AppError('Invalid user ID', 400);
  }

  if (typeof blocked !== 'boolean') {
    throw new AppError('blocked must be a boolean', 400);
  }

  if (userId === req.user.id) {
    throw new AppError('You cannot block your own account', 400);
  }

  const user = await User.findById(userId).select(
    'name email role isBlocked storageUsed storageLimit createdAt',
  );

  if (!user) {
    throw new AppError('User not found', 404);
  }

  if (user.role === 'ADMIN') {
    throw new AppError('Admin accounts cannot be blocked here', 400);
  }

  user.isBlocked = blocked;
  await user.save();

  await createAuditLog({
    action: blocked ? AUDIT_ACTIONS.ADMIN_BLOCK_USER : AUDIT_ACTIONS.ADMIN_UNBLOCK_USER,
    status: AUDIT_STATUS.SUCCESS,
    user: req.user.id,
    resourceType: RESOURCE_TYPES.USER,
    resourceId: user.id,
    details: { targetEmail: user.email },
    req,
  });

  return res.status(200).json({
    success: true,
    data: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      isBlocked: user.isBlocked,
      storageUsed: user.storageUsed,
      storageLimit: user.storageLimit,
      createdAt: user.createdAt,
    },
  });
});
