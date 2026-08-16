import crypto from "crypto";
import Share from "../models/share.model.js";
import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import { configDotenv } from "dotenv";
import { decryptFile, generateHashFromBuffer} from "./encryption.service.js";
import { createAuditLog } from "./audit.service.js";
import { AUDIT_ACTIONS,AUDIT_STATUS,RESOURCE_TYPES } from "../utils/constants.js";

export const createShareLink = async (
  req,
  fileId,
  userId,
  maxDownloads = null
) => {

  if (
    maxDownloads !== null &&
    (
        !Number.isInteger(maxDownloads) ||
        maxDownloads < 1
    )
  ) {
      throw new AppError(
          "maxDownloads must be a positive integer",
          400
      );
  }

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

  const share = await Share.create({
    file:file._id,
    owner:userId,
    token:hashedToken,
    expiresAt,
    maxDownloads
  });

  await createAuditLog({
    req,
    user: userId,
    action: AUDIT_ACTIONS.CREATE_SHARE,
    resourceType: RESOURCE_TYPES.SHARE,
    resourceId: share._id,
    status: AUDIT_STATUS.SUCCESS,
    details: {
        filename: file.originalName
    }
  });

  return {
    success:true,
    shareId:share._id,
    shareLink:
`${process.env.APP_URL}/share/${token}`,
    expiresAt
  };
};

export const downloadSharedFileService =
async(req,token)=>{

  const hashedToken = crypto.createHash("sha256")
  .update(token)
  .digest("hex");

  const share =
  await Share.findOne({
    token:hashedToken
  });

  if(!share){
    await createAuditLog({
      req,
      action: AUDIT_ACTIONS.INVALID_SHARE,
      status: AUDIT_STATUS.FAILED,
      details: {
          token
      }
    });
    throw new AppError(
    "Invalid share link",
    404
    );
  }

  if(share.isRevoked){
    throw new AppError(
      "Share link revoked",
      403
    );
  }

  if (share.maxDownloads !== null &&
    share.downloadCount >= share.maxDownloads) {

    throw new AppError(
      "Download limit exceeded",
      403
    );
  }

  if(share.expiresAt < new Date()){
    await createAuditLog({
      req,
      action: AUDIT_ACTIONS.INVALID_SHARE,
      status: AUDIT_STATUS.FAILED,
      details: {
          token
      }
    });
    throw new AppError(
    "Share link expired",
    410
    );

  }

  const file = await File.findById(
    share.file
  );

  if(!file){

    throw new AppError(
    "File not found",
    404
    );

  }

  const buffer = decryptFile(
    file.path,
    file.iv
  );

  const hash =generateHashFromBuffer(buffer);

  if(hash !== file.hash){
    throw new AppError(
      "Integrity check failed",
      500
    );
  }

  const updatedShare = await Share.findOneAndUpdate(
    {
      _id: share._id,

      $or: [
        { maxDownloads: null },
        { $expr: { $lt: ["$downloadCount", "$maxDownloads"] } }
      ]
    },
    {
      $inc: {
        downloadCount: 1
      }
    },
    {
      new: true
    }
  );

  if (!updatedShare) {
    throw new AppError(
      "Download limit exceeded",
      403
    );
  }

  await createAuditLog({
    req,
    user: null,
    action: AUDIT_ACTIONS.DOWNLOAD_SHARE,
    resourceType: RESOURCE_TYPES.SHARE,
    resourceId: share._id,
    status: AUDIT_STATUS.SUCCESS,
    details: {
        filename: file.originalName
    }
  });



  return{
    metadata:file,
    buffer
  };

};


export const revokeShareLink = async (req,shareId, userId) => {
    const share = await Share.findById(shareId);

    if (!share) {
        throw new AppError("Share link not found", 404);
    }

    if (!share.owner) {
        throw new AppError("Share owner missing", 500);
    }

    if (!userId) {
        throw new AppError("User not authenticated", 401);
    }

    if (String(share.owner) !== String(userId)) {
        throw new AppError("Access denied", 403);
    }

    if (share.isRevoked) {
        throw new AppError("Share link already revoked", 400);
    }

    share.isRevoked = true;

    await share.save();
    
    await createAuditLog({
      req,
      user: userId,
      action: AUDIT_ACTIONS.REVOKE_SHARE,
      resourceType: RESOURCE_TYPES.SHARE,
      resourceId: share._id,
      status: AUDIT_STATUS.SUCCESS
    });

    return {
        success: true,
        message: "Share link revoked successfully"
    };
};