import multer from "multer";
import path from "path";
import fs from "fs";

const uploadDir = "uploads";

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, {
        recursive: true
    });
}


const ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain"
};

const fileFilter = (req, file, cb) => {

    const filename =
        file.originalname || "";

    if (filename.includes("\0")) {
        return cb(
            new Error("Invalid filename")
        );
    }

    if (!filename.trim()) {
        return cb(
            new Error("Invalid filename")
        );
    }

    if (
        filename.includes("..") ||
        filename.includes("/") ||
        filename.includes("\\")
    ) {
        return cb(
            new Error("Invalid filename")
        );
    }

    if (filename.length > 255) {
        return cb(
            new Error("Filename too long")
        );
    }

    const extension =
        path.extname(filename).toLowerCase();

    const expectedMime =
        ALLOWED_TYPES[extension];

    if (!expectedMime) {
        return cb(
            new Error("Unsupported file type")
        );
    }

    if (file.mimetype !== expectedMime) {
        return cb(
            new Error(
                "File extension and MIME type do not match"
            )
        );
    }

    cb(null, true);
};

const storage = multer.diskStorage({

    destination: (req, file, cb) => {

        cb(null, uploadDir);

    },

    filename: (req, file, cb) => {

        const original =
            path.basename(
                file.originalname || "file"
            );

        const extension =
            path.extname(original)
                .toLowerCase();

        const base =
            path.basename(
                original,
                path.extname(original)
            );

        const safeBase =
            base
                .replace(
                    /[^a-zA-Z0-9_-]/g,
                    "_"
                )
                .slice(0, 100);

        const safeExtension =
            extension
                .replace(
                    /[^a-zA-Z0-9.]/g,
                    ""
                )
                .slice(0, 20);

        const filename =
            `${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}-${safeBase || "file"}${safeExtension}`;

        cb(null, filename);
    }
});

export const upload = multer({

    storage,

    fileFilter,

    limits: {
        fileSize: 10 * 1024 * 1024,
        files: 1
    }

});