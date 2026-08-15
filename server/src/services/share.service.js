import crypto from "crypto";
import Share from "../models/share.model.js";
import File from "../models/file.model.js";
import AppError from "../utils/AppError.js";
import { configDotenv } from "dotenv";
import { decryptFile, generateHashFromBuffer} from "./encryption.service.js";
import { createAuditLog } from "./audit.service.js";
import { AUDIT_ACTIONS,AUDIT_STATUS } from "../utils/constants.js";

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

  const share = await Share.create({
    file:file._id,
    owner:userId,
    token:hashedToken,
    expiresAt
  });

  await createAuditLog({
    user: userId,
    action: AUDIT_ACTIONS.CREATE_SHARE,
    resourceType: "SHARE",
    resourceId: share._id,
    status: AUDIT_STATUS.SUCCESS,
    details: {
        file: file.originalName
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
async(token)=>{

  const hashedToken = crypto.createHash("sha256")
  .update(token)
  .digest("hex");

  const share =
  await Share.findOne({
    token:hashedToken
  });

  if(!share){
    await createAuditLog({
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

  if(share.expiresAt < new Date()){
    await createAuditLog({
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

  await createAuditLog({
    user: null,
    action: AUDIT_ACTIONS.DOWNLOAD_SHARE,
    resourceType: "SHARE",
    resourceId: share._id,
    status: AUDIT_STATUS.SUCCESS,
    details: {
        filename: file.originalName
    }
  });

  share.downloadCount++;
  await share.save();


  return{
    metadata:file,
    buffer
  };

};


export const revokeShareLink = async (shareId, userId) => {
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
      user: userId,
      action: AUDIT_ACTIONS.REVOKE_SHARE,
      resourceType: "SHARE",
      resourceId: share._id,
      status: AUDIT_STATUS.SUCCESS
  });

    return {
        success: true,
        message: "Share link revoked successfully"
    };
};