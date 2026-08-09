import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import fs from "fs";

export const saveFile = async (file, user) => {

    if (!file) {

        throw new AppError(
            "No file uploaded",
            400
        );
    }

    const uploadedFile = await File.create({
        originalName: file.originalname,
        storedName: file.filename,
        mimeType: file.mimetype,
        size: file.size,
        path: file.path,
        owner: user.id
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
    return file;
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
    return {
        success: true,
        message: "File deleted successfully"
    };
};