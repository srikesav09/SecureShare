import { asyncHandler } from '../utils/asyncHandler.js';
import {
  saveFile,
  getFiles,
  importSharedFile,
  downloadFileService,
  deleteFileService,
  analyzeStoredFile,
} from '../services/file.service.js';
import { downloadSharedFileService } from '../services/share.service.js';
import { assertTrustedShareLink } from '../utils/shareLinkSecurity.js';

export const uploadFile = asyncHandler(async (req, res) => {
  const result = await saveFile(req, req.file, req.user);

  return res.status(201).json(result);
});

export const getMyFiles = asyncHandler(async (req, res) => {
  const result = await getFiles(req.user.id);

  return res.status(200).json(result);
});

export const importFromShare = asyncHandler(async (req, res) => {
  const { shareLink, password } = req.body;
  const token = assertTrustedShareLink(shareLink);

  const sharedRequest = {
    ...req,
    headers: { ...req.headers, 'x-share-password': password || undefined },
  };
  const sharedFile = await downloadSharedFileService(sharedRequest, token);
  const result = await importSharedFile(req, sharedFile, req.user);

  return res.status(201).json({ ...result, message: 'Shared file saved to your vault' });
});

export const downloadFile = asyncHandler(async (req, res) => {
  const result = await downloadFileService(req, req.params.id, req.user.id);

  res.setHeader('Content-Disposition', `attachment; filename="${result.metadata.originalName}"`);

  res.setHeader('Content-Type', result.metadata.mimeType);

  return res.send(result.buffer);
});

export const deleteFile = asyncHandler(async (req, res) => {
  const result = await deleteFileService(req, req.params.id, req.user.id);

  return res.status(200).json(result);
});

export const analyzeFile = asyncHandler(async (req, res) => {
  const result = await analyzeStoredFile(req, req.params.id, req.user.id);
  return res.status(200).json(result);
});
