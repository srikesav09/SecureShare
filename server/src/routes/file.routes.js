import express from "express";

import {
    authenticate
} from "../middleware/auth.middleware.js";

import {
    upload
} from "../middleware/upload.middleware.js";

import {
    uploadFile,
    getMyFiles,
    downloadFile,
    deleteFile
} from "../controllers/file.controller.js";

import {
    uploadLimiter
} from "../middleware/rateLimiter.middleware.js";

import {
    validateFileSignature
} from "../middleware/fileSignature.middleware.js";

import multer from "multer";

const router = express.Router();


router.post(
    "/upload",
    authenticate,
    uploadLimiter,


    (req, res, next) => {
        upload.single("file")(req, res, (err) => {

            if (err) {

                if (err instanceof multer.MulterError) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid file upload"
                    });
                }

                return res.status(400).json({
                    success: false,
                    message: "Invalid file upload"
                });
            }

            next();
        });
    },

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