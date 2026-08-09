import crypto from "crypto";
import fs from "fs";

const KEY = Buffer.from(
  process.env.ENCRYPTION_KEY,
  "hex"
);

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

export const decryptFile = (
    encryptedPath,
    iv
) => {
    const encryptedData =
        fs.readFileSync(
            encryptedPath
        );

    const decipher =
        crypto.createDecipheriv(
            "aes-256-cbc",
            KEY,
            Buffer.from(iv, "hex")
        );

    const decrypted =
        Buffer.concat([
            decipher.update(
                encryptedData
            ),
            decipher.final()
        ]);
    return decrypted;
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