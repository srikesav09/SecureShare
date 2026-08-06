import multer from "multer";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import path from "path";

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

const fileFilter = (req, file, cb) => {
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Unsupported file type"));
  }
};

export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});