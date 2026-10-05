import express from 'express';
import {
  register,
  login,
  profile,
  updatePassword,
  logout,
  sessions,
  logoutOtherSessions,
  revoke,
} from '../controllers/auth.controller.js';
import { validate } from '../middleware/validate.middleware.js';
import { registerSchema, loginSchema, changePasswordSchema } from '../validators/auth.validator.js';
import { authenticate } from '../middleware/auth.middleware.js';
import {
  loginLimiter,
  registerLimiter,
  passwordChangeLimiter,
} from '../middleware/rateLimiter.middleware.js';

const router = express.Router();

router.post('/register', registerLimiter, validate(registerSchema), register);

router.post('/login', loginLimiter, validate(loginSchema), login);

router.get('/profile', authenticate, profile);

router.patch(
  '/password',
  authenticate,
  passwordChangeLimiter,
  validate(changePasswordSchema),
  updatePassword,
);

router.post('/logout', authenticate, logout);
router.get('/sessions', authenticate, sessions);
router.delete('/sessions/others', authenticate, logoutOtherSessions);
router.delete('/sessions/:sessionId', authenticate, revoke);

export default router;
