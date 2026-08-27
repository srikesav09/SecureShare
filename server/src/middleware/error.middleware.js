import multer from "multer";

export const errorHandler = (err, req, res, next) => {
    console.error(err);

    if (err instanceof multer.MulterError) {

        let message = "Invalid file upload request.";

        if (err.code === "LIMIT_UNEXPECTED_FILE") {
            message = "Unexpected upload field.";
        }

        if (err.code === "LIMIT_FILE_SIZE") {
            message = "Uploaded file is too large.";
        }

        return res.status(400).json({
            success: false,
            message,
            requestId: req.requestId,
            errors: []
        });
    }

    const statusCode = err.statusCode || 500;

    return res.status(statusCode).json({
        success: false,
        message: err.message || "Internal Server Error",
        requestId: req.requestId,
        errors: []
    });
};