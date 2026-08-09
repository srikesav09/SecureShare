import express from "express";

import { authenticate } from "../middleware/auth.middleware.js";
import { upload } from "../middleware/upload.middleware.js";
import { uploadFile } from "../controllers/file.controller.js";
import { getMyFiles } from "../controllers/file.controller.js";
import { downloadFile } from "../controllers/file.controller.js";

const router = express.Router();

router.post(
    "/upload",
    authenticate,
    upload.single("file"),
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

export default router;