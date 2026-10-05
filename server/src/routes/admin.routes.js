import express from 'express';

import {
  getAuditLogs,
  getDashboard,
  getQuarantineQueue,
  releaseQuarantined,
} from '../controllers/admin.controller.js';
import { authenticate } from '../middleware/auth.middleware.js';
import { requireAdmin } from '../middleware/admin.middleware.js';

const router = express.Router();

router.get('/audit-logs', authenticate, requireAdmin, getAuditLogs);
router.get('/dashboard', authenticate, requireAdmin, getDashboard);
router.get('/quarantine', authenticate, requireAdmin, getQuarantineQueue);
router.post('/quarantine/:fileId/release', authenticate, requireAdmin, releaseQuarantined);

export default router;
