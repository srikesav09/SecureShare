import crypto from "crypto";
import Share from "../models/share.model.js";
import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import { configDotenv } from "dotenv";

export const createShareLink = async (
  fileId,
  userId
) => {

  const file =await File.findById(fileId);

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
  const token =
    crypto.randomBytes(32)
    .toString("hex");

  const hashedToken =
    crypto.createHash("sha256")
      .update(token)
      .digest("hex");
  const expiresAt =
    new Date(
      Date.now() +
      24 * 60 * 60 * 1000
    );

  await Share.create({
    file:file._id,
    owner:userId,
    token:hashedToken,
    expiresAt
  });
  return {
    success:true,
    shareLink:
`${process.env.APP_URL}/share/${token}`,
    expiresAt
  };
};