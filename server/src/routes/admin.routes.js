import express from "express";

import { getAuditLogs } from "../controllers/admin.controller.js";
import { authenticate } from "../middleware/auth.middleware.js";
import { requireAdmin } from "../middleware/admin.middleware.js";


const router = express.Router();

router.get(
  "/audit-logs",
  authenticate,
  requireAdmin,
  getAuditLogs
);

export default router;