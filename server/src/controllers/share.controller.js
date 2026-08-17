import { asyncHandler } from "../utils/asyncHandler.js";
import { createShareLink,revokeShareLink } from "../services/share.service.js";
import { downloadSharedFileService } from "../services/share.service.js";

export const shareFile = asyncHandler(
      async (req,res)=>{

        const result =await createShareLink(
          req,
          req.params.fileId,
          req.user.id,
          req.body.maxDownloads,
          req.body.password
        );

      res.status(201).json(result);

});

export const downloadSharedFile =
  asyncHandler(async(req,res)=>{

    const result = await downloadSharedFileService(
      req,
      req.params.token
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${result.metadata.originalName}"`
    );

    res.setHeader(
      "Content-Type",
      result.metadata.mimeType
    );


  return res.send(
    result.buffer
  );

});

export const revokeShare = asyncHandler(async (req, res) => {

    const result = await revokeShareLink(
        req,
        req.params.shareId,
        req.user.id
    );

    res.status(200).json(result);

});