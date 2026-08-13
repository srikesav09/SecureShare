import express from "express";
import { downloadSharedFile } from "../controllers/share.controller.js";

const router = express.Router();

router.get("/:token", downloadSharedFile);

export default router;