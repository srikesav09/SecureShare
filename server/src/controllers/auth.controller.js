import {
  registerUser,
  loginUser,
  getProfile,
  changePassword,
  logoutSession,
  getSessions,
  revokeAllSessions,
  revokeSession,
} from '../services/auth.service.js';

import { asyncHandler } from '../utils/asyncHandler.js';

export const register = asyncHandler(async (req, res) => {
  const result = await registerUser(req.body);

  return res.status(201).json(result);
});

export const login = asyncHandler(async (req, res) => {
  const result = await loginUser(req, req.body);
  return res.status(200).json(result);
});

export const profile = asyncHandler(async (req, res) => {
  const result = await getProfile(req.user.id);

  return res.status(200).json(result);
});

export const updatePassword = asyncHandler(async (req, res) => {
  const result = await changePassword(
    req,
    req.user.id,
    req.body.currentPassword,
    req.body.newPassword,
  );

  return res.status(200).json(result);
});

export const logout = asyncHandler(async (req, res) => {
  const result = await logoutSession(req.user.id, req.user.sessionId);
  return res.status(200).json(result);
});

export const sessions = asyncHandler(async (req, res) => {
  const result = await getSessions(req.user.id, req.user.sessionId);
  return res.status(200).json(result);
});

export const logoutOtherSessions = asyncHandler(async (req, res) => {
  const result = await revokeAllSessions(req.user.id, req.user.sessionId);
  return res.status(200).json(result);
});

export const revoke = asyncHandler(async (req, res) => {
  const result = await revokeSession(req.user.id, req.params.sessionId, req.user.sessionId);
  return res.status(200).json(result);
});
