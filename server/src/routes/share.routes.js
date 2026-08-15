import express from "express";

import { authenticate } from "../middleware/auth.middleware.js";
import { createShareLimiter } from "../middleware/rateLimiter.middleware.js";

import {
    shareFile,
    revokeShare
} from "../controllers/share.controller.js";

const router = express.Router();

router.post(
    "/:fileId",
    authenticate,
    createShareLimiter,
    shareFile
);

router.delete(
    "/:shareId",
    authenticate,
    revokeShare
);

export default router;