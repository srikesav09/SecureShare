import express from 'express';

import {
  getAuditLogs,
  getDashboard,
  listUsers,
  setUserBlocked,
} from '../controllers/admin.controller.js';
import { authenticate } from '../middleware/auth.middleware.js';
import { requireAdmin } from '../middleware/admin.middleware.js';

const router = express.Router();

router.get('/audit-logs', authenticate, requireAdmin, getAuditLogs);
router.get('/dashboard', authenticate, requireAdmin, getDashboard);
router.get('/users', authenticate, requireAdmin, listUsers);
router.patch('/users/:userId/block', authenticate, requireAdmin, setUserBlocked);

export default router;
