import { asyncHandler } from "../utils/asyncHandler.js";
import { saveFile } from "../services/file.service.js";

export const uploadFile = asyncHandler(async (req, res) => {

    const result = await saveFile(req.file, req.user);

    return res.status(201).json(result);

});