import express from "express";

import { authenticate } from "../middleware/auth.middleware.js";
import { shareFile } from "../controllers/share.controller.js";

const router = express.Router();

router.post(
  "/:fileId",
  authenticate,
  shareFile
);

export default router;