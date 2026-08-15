import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import fs from "fs";
import { generateHash,encryptFile,decryptFile,generateHashFromBuffer } from "./encryption.service.js";
import { createAuditLog } from "./audit.service.js";
import { AUDIT_ACTIONS,AUDIT_STATUS } from "../utils/constants.js";

export const saveFile = async (file, user) => {

    if (!file) {

        throw new AppError(
            "No file uploaded",
            400
        );
    }

    const hash =generateHash(file.path);
    const encryption =encryptFile(file.path);

    const uploadedFile = await File.create({
        originalName: file.originalname,
        storedName: file.filename,
        mimeType: file.mimetype,
        size: file.size,
        path: encryption.encryptedPath,
        owner: user.id,
        iv:encryption.iv,
        hash,
        encrypted: true
    });
    await createAuditLog({
        req,
        user: user.id,
        action: AUDIT_ACTIONS.UPLOAD_FILE,
        resourceType: "FILE",
        resourceId: uploadedFile._id,
        status: AUDIT_STATUS.SUCCESS,
        details: {
            filename: uploadedFile.originalName
        }
    });
    return {
        success: true,
        message: "File uploaded successfully",
        data: uploadedFile
    };
};

export const getFiles = async (userId) => {
    const files = await File.find({
        owner: userId
    }).sort({
        createdAt: -1
    });
    return {
        success: true,
        message: "Files fetched successfully",
        data: files
    };
};

export const downloadFileService = async (
    fileId,
    userId
) => {
    const file = await File.findById(fileId);
    if (!file) {
        throw new AppError(
            "File not found",
            404
        );
    }
    if (
        file.owner.toString() !==
        userId.toString()
    ) {
        throw new AppError(
            "Access denied",
            403
        );
    }
    if (!fs.existsSync(file.path)) {
        throw new AppError(
            "File not found on server",
            404
        );
    }
    const decrypted =decryptFile(
          file.path,
          file.iv
      );

    const currentHash =generateHashFromBuffer(decrypted);

    if (
        currentHash !==
        file.hash
    ){ 
      throw new AppError(
      "Integrity check failed",
      500
      );
    }
    await createAuditLog({

        user: userId,
        action: AUDIT_ACTIONS.DOWNLOAD_FILE,
        resourceType: "FILE",
        resourceId: file._id,
        status: AUDIT_STATUS.SUCCESS,
        details: {
            filename: file.originalName
        }
    });

    return {
      metadata:file,
      buffer:decrypted
    };
};

export const deleteFileService = async (
    fileId,
    userId
) => {

    const file = await File.findById(fileId);
    if (!file) {
        throw new AppError("File not found", 404);
    }
    if (
        file.owner.toString() !==
        userId.toString()
    ) {
        throw new AppError("Access denied", 403);
    }
    if (fs.existsSync(file.path)) {
        fs.unlinkSync(file.path);
    }
    await File.findByIdAndDelete(fileId);
    await createAuditLog({
        user: userId,
        action: AUDIT_ACTIONS.DELETE_FILE,
        resourceType: "FILE",
        resourceId: file._id,
        status: AUDIT_STATUS.SUCCESS,
        details: {
            filename: file.originalName
        }
    });

    return {
        success: true,
        message: "File deleted successfully"
    };
};