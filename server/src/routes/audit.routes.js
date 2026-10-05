import express from 'express';

import { authenticate } from '../middleware/auth.middleware.js';
import { getMyAuditLogs } from '../controllers/audit.controller.js';

const router = express.Router();

router.get('/', authenticate, getMyAuditLogs);

export default router;
