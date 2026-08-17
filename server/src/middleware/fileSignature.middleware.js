import fs from "fs";
import path from "path";
import AppError from "../utils/AppError.js";

const signatures = {

  ".pdf": {
    mimeType: "application/pdf",
    check: (buffer) => {
      return buffer.subarray(0, 5).toString() === "%PDF-";
    },
  },

  ".png": {
    mimeType: "image/png",
    check: (buffer) => {

      const signature = Buffer.from([
        0x89,
        0x50,
        0x4e,
        0x47,
        0x0d,
        0x0a,
        0x1a,
        0x0a,
      ]);

      return buffer.subarray(0, 8).equals(signature);
    },
  },

  ".jpg": {
    mimeType: "image/jpeg",
    check: (buffer) => {
      return (
        buffer[0] === 0xff &&
        buffer[1] === 0xd8 &&
        buffer[2] === 0xff
      );
    },
  },

  ".jpeg": {
    mimeType: "image/jpeg",
    check: (buffer) => {
      return (
        buffer[0] === 0xff &&
        buffer[1] === 0xd8 &&
        buffer[2] === 0xff
      );
    },
  },

  ".docx": {
    mimeType:
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

    check: (buffer) => {

      return (
        buffer[0] === 0x50 &&
        buffer[1] === 0x4b &&
        buffer[2] === 0x03 &&
        buffer[3] === 0x04
      );
    },
  },

  ".txt": {
    mimeType: "text/plain",

    check: (buffer) => {
      try {

        new TextDecoder("utf-8", {
          fatal: true,
        }).decode(buffer);

        return true;
      } catch {
        return false;
      }
    },
  },
};

export const validateFileSignature = async (
  req,
  res,
  next
) => {
  if (!req.file) {
    return next();
  }

  const filePath = req.file.path;

  try {
    const extension = path
      .extname(req.file.originalname)
      .toLowerCase();

    const signature =
      signatures[extension];

    if (!signature) {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      return next(
        new AppError(
          "Unsupported file extension",
          400
        )
      );
    }

    const buffer = fs.readFileSync(filePath);

    const valid =
      signature.check(buffer);

    if (!valid) {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      return next(
        new AppError(
          "File content does not match its extension",
          400
        )
      );
    }


    req.file.mimetype = signature.mimeType;

    next();

  } catch (error) {

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    next(
      new AppError(
        "Unable to validate uploaded file",
        400
      )
    );
  }
};