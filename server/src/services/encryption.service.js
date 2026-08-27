import crypto from "crypto";
import fs from "fs";
import  AppError from "../utils/AppError.js";

const rawKey = process.env.ENCRYPTION_KEY;

if (!rawKey) {
  throw new AppError(
    "ENCRYPTION_KEY is not configured",
    500
  );
}

if (!/^[0-9a-fA-F]{64}$/.test(rawKey)) {
  throw new AppError(
    "ENCRYPTION_KEY must be a 64-character hexadecimal string",
    500
  );
}
const KEY = Buffer.from(rawKey, "hex");

export const encryptFile = (filePath) => {

  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    KEY,
    iv
  );

  const data = fs.readFileSync(filePath);

  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final(),
  ]);

  const encryptedPath = filePath + ".enc";

  fs.writeFileSync(
    encryptedPath,
    encrypted
  );

  fs.unlinkSync(filePath);

  return {
    encryptedPath,
    iv: iv.toString("hex"),
  };
};


export const generateHash = (filePath) => {
    const data =fs.readFileSync(filePath);

    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
};

export const generateHashFromBuffer = (buffer) => {

    return crypto
        .createHash("sha256")
        .update(buffer)
        .digest("hex");
};

export const decryptBuffer = (
    encryptedData,
    iv
) => {
    const decipher =
        crypto.createDecipheriv(
            "aes-256-cbc",
            KEY,
            Buffer.from(iv, "hex")
        );

    return Buffer.concat([
        decipher.update(encryptedData),
        decipher.final()
    ]);
};