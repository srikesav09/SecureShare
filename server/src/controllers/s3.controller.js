import { asyncHandler } from "../utils/asyncHandler.js";
import {
  uploadToS3,
  downloadFromS3,
  deleteFromS3,
} from "../services/s3.service.js";

export const testS3 = asyncHandler(
  async (req, res) => {

    const key =
      `test/${Date.now()}-secureshare.txt`;

    const content =
      "SecureShare S3 test";

    await uploadToS3({
      key,
      body: Buffer.from(content),
      contentType: "text/plain",
    });

    const downloaded =
      await downloadFromS3(key);

    const downloadedText =
      downloaded.toString("utf-8");

    await deleteFromS3(key);

    return res.status(200).json({
      success: true,
      message: "S3 test successful",
      data: {
        key,
        downloadedText,
      },
    });
  }
);