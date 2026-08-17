import express from "express";
import { downloadSharedFile } from "../controllers/share.controller.js";
import { shareLimiter } from "../middleware/rateLimiter.middleware.js";

const router = express.Router();

router.get("/:token", shareLimiter, downloadSharedFile);

export default router;