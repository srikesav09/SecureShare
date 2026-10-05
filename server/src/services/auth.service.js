import bcrypt from 'bcrypt';

import User from '../models/user.model.js';
import AppError from '../utils/AppError.js';
import { generateToken } from '../utils/jwt.js';
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

export const loginUser = async (loginData) => {
  const { email, password } = loginData;
  const user = await User.findOne({ email });
  if (!user) {
    throw new AppError('Invalid email or password', 401);
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    throw new AppError('Invalid email or password', 401);
  }
  const token = generateToken({
    id: user.id,
    role: user.role,
  });

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
