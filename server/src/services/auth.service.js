import bcrypt from 'bcrypt';

import User from '../models/user.model.js';
import AppError from '../utils/AppError.js';
import { generateToken } from '../utils/jwt.js';
import Session from '../models/session.model.js';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { createAuditLog } from './audit.service.js';
import { AUDIT_ACTIONS, AUDIT_STATUS, RESOURCE_TYPES } from '../utils/constants.js';

export const registerUser = async (userData) => {
  const { name, email, password } = userData;
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new AppError('Email already exists', 409);
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
    role: 'USER',
  });

  return {
    success: true,
    message: 'User registered successfully',
    data: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  };
};

export const loginUser = async (req, loginData) => {
  const { email, password } = loginData;
  const user = await User.findOne({ email });
  if (!user) {
    throw new AppError('Invalid email or password', 401);
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    throw new AppError('Invalid email or password', 401);
  }
  const tokenId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await Session.create({
    user: user._id,
    tokenId,
    userAgent: req.headers['user-agent'] || 'Unknown device',
    ipAddress: req.ip,
    expiresAt,
  });

  const token = generateToken(
    {
      id: user.id,
      role: user.role,
    },
    { tokenId },
  );

  return {
    success: true,
    message: 'Login successful',
    data: {
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    },
  };
};

export const logoutSession = async (userId, sessionId) => {
  await Session.updateOne({ _id: sessionId, user: userId }, { $set: { revokedAt: new Date() } });
  return { success: true, message: 'Session signed out' };
};

export const getSessions = async (userId, currentSessionId) => {
  const sessions = await Session.find({
    user: userId,
    revokedAt: null,
    expiresAt: { $gt: new Date() },
  })
    .sort({ lastSeenAt: -1 })
    .lean();

  return {
    success: true,
    data: sessions.map((session) => ({
      id: session._id,
      device: session.userAgent,
      ipAddress: session.ipAddress,
      lastSeenAt: session.lastSeenAt,
      createdAt: session.createdAt,
      current: String(session._id) === String(currentSessionId),
    })),
  };
};

export const revokeAllSessions = async (userId, currentSessionId) => {
  await Session.updateMany(
    { user: userId, _id: { $ne: currentSessionId }, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  return { success: true, message: 'Other sessions revoked' };
};

export const revokeSession = async (userId, sessionId, currentSessionId) => {
  if (!mongoose.Types.ObjectId.isValid(sessionId)) {
    throw new AppError('Invalid session ID', 400);
  }

  if (String(sessionId) === String(currentSessionId)) {
    throw new AppError('Use sign out to revoke the current session', 400);
  }

  const result = await Session.updateOne(
    { _id: sessionId, user: userId, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );

  if (!result.matchedCount) throw new AppError('Session not found', 404);
  return { success: true, message: 'Session revoked' };
};

export const getProfile = async (userId) => {
  const user = await User.findById(userId).select('-password');
  if (!user) {
    throw new AppError('User not found', 404);
  }
  return {
    success: true,
    message: 'Profile fetched successfully',
    data: user,
  };
};

export const changePassword = async (req, userId, currentPassword, newPassword) => {
  const user = await User.findById(userId);
  if (!user) throw new AppError('User not found', 404);

  const currentPasswordValid = await bcrypt.compare(currentPassword, user.password);
  if (!currentPasswordValid) {
    await createAuditLog({
      req,
      user: userId,
      action: AUDIT_ACTIONS.PASSWORD_CHANGE,
      resourceType: RESOURCE_TYPES.USER,
      resourceId: userId,
      status: AUDIT_STATUS.FAILED,
      details: { reason: 'Current password mismatch' },
    });
    throw new AppError('Current password is incorrect', 401);
  }

  if (currentPassword === newPassword) {
    throw new AppError('New password must be different from the current password', 400);
  }

  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();

  await createAuditLog({
    req,
    user: userId,
    action: AUDIT_ACTIONS.PASSWORD_CHANGE,
    resourceType: RESOURCE_TYPES.USER,
    resourceId: userId,
    status: AUDIT_STATUS.SUCCESS,
  });

  return { success: true, message: 'Password changed successfully' };
};
