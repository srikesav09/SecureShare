import multer from "multer";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import path from "path";
import AppError from "../utils/AppError.js";

const uploadDir = "uploads";

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },

  filename(req, file, cb) {
    const extension = path.extname(file.originalname);
    cb(null, `${uuidv4()}${extension}`);
  },
});

const allowedMimeTypes = [
  "application/pdf",
  "image/png",
  "image/jpeg",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/plain",
];

const mimeTypeByExtension = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".docx":
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".txt": "text/plain",
  };

  const fileFilter = (req, file, cb) => {
    const extension = path
      .extname(file.originalname)
      .toLowerCase();


    const allowedExtensions = [
      ".pdf",
      ".png",
      ".jpg",
      ".jpeg",
      ".docx",
      ".txt",
    ];

    const extensionAllowed =
      allowedExtensions.includes(extension);

    const mimeAllowed =
      allowedMimeTypes.includes(file.mimetype);

    if (mimeAllowed && extensionAllowed) {
      return cb(null, true);
    }

    if (
      file.mimetype === "application/octet-stream" &&
      extensionAllowed
    ) {
      file.mimetype = mimeTypeByExtension[extension];

      return cb(null, true);
    }

    return cb(
      new AppError("Unsupported file type", 400),
      false
    );
  };

export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});