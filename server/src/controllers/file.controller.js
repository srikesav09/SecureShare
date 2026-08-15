import { asyncHandler } from "../utils/asyncHandler.js";
import { saveFile } from "../services/file.service.js";
import { getFiles } from "../services/file.service.js";
import { downloadFileService } from "../services/file.service.js";
import { deleteFileService } from "../services/file.service.js";

export const uploadFile = asyncHandler(async (req, res) => {
    const result = await saveFile(req,req.file, req.user);
    return res.status(201).json(result);
});

export const getMyFiles = asyncHandler(async (req, res) => {
    const result = await getFiles(req.user.id);
    return res.status(200).json(result);
});

export const downloadFile = asyncHandler(async (req, res) => {
    const result =await downloadFileService(
      req,
      req.params.id,
      req.user.id
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${result.metadata.originalName}"`
    );
    res.setHeader(
      "Content-Type",
      result.metadata.mimeType
    );
    res.send(
      result.buffer
    );
});

export const deleteFile = asyncHandler(async (req, res) => {

    const result = await deleteFileService(
        req,
        req.params.id,
        req.user.id
    );
    return res.status(200).json(result);

});