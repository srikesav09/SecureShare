import express from "express";
import { testS3 } from "../controllers/s3.controller.js";

const router = express.Router();

router.get("/test", testS3);

export default router;