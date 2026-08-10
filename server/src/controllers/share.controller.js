import { asyncHandler } from "../utils/asyncHandler.js";
import { createShareLink } from "../services/share.service.js";

export const shareFile = asyncHandler(
      async (req,res)=>{

        const result =await createShareLink(
        req.params.fileId,
        req.user.id
        );

      res.status(201).json(result);

});