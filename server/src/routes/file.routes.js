import express from "express";

import { authenticate } from "../middleware/auth.middleware.js";
import { upload } from "../middleware/upload.middleware.js";
import { uploadFile } from "../controllers/file.controller.js";
import { getMyFiles } from "../controllers/file.controller.js";
import { downloadFile } from "../controllers/file.controller.js";
import { deleteFile } from "../controllers/file.controller.js";
import { uploadLimiter } from "../middleware/rateLimiter.middleware.js";
import { validateFileSignature } from "../middleware/fileSignature.middleware.js";

const router = express.Router();

router.post(
    "/upload",
    authenticate,
    uploadLimiter,
    upload.single("file"),
    validateFileSignature,
    uploadFile
);

router.get(
    "/",
    authenticate,
    getMyFiles
);

router.get(
  "/:id/download",
  authenticate,
  downloadFile
);

router.delete(
    "/:id",
    authenticate,
    deleteFile
);

export default router;