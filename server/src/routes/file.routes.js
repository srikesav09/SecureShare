import express from 'express';

import { authenticate } from '../middleware/auth.middleware.js';

import { upload } from '../middleware/upload.middleware.js';

import {
  uploadFile,
  importFromShare,
  getMyFiles,
  downloadFile,
  deleteFile,
  analyzeFile,
} from '../controllers/file.controller.js';

import { uploadLimiter } from '../middleware/rateLimiter.middleware.js';

import { validateFileSignature } from '../middleware/fileSignature.middleware.js';

import multer from 'multer';

const router = express.Router();

router.post(
  '/upload',
  authenticate,
  uploadLimiter,

  (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError) {
          return res.status(400).json({
            success: false,
            message: 'Invalid file upload',
          });
        }

        return res.status(400).json({
          success: false,
          message: 'Invalid file upload',
        });
      }

      next();
    });
  },

  validateFileSignature,

  uploadFile,
);

router.get('/', authenticate, getMyFiles);

router.post('/import-share', authenticate, uploadLimiter, importFromShare);

router.post('/:id/security-analysis', authenticate, analyzeFile);

router.get('/:id/download', authenticate, downloadFile);

router.delete('/:id', authenticate, deleteFile);

export default router;
