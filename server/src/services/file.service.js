import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";

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