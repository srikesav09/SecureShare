import { asyncHandler } from "../utils/asyncHandler.js";
import { saveFile } from "../services/file.service.js";
import { getFiles } from "../services/file.service.js";

export const uploadFile = asyncHandler(async (req, res) => {

    const result = await saveFile(req.file, req.user);

    return res.status(201).json(result);

});

export const getMyFiles = asyncHandler(async (req, res) => {

    const result = await getFiles(req.user.id);

    return res.status(200).json(result);

});