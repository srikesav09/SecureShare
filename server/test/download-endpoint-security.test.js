import "./env.js";
import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert/strict";
import request from "supertest";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import mongoose from "mongoose";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const TEST_PASSWORD = "Password@123";

let user1;
let user2;

let token1;
let token2;


/* ============================================================
   TEST USER CREATION
   ============================================================ */

const createTestUser = async (
    email,
    name
) => {

    const hashedPassword =
        await bcrypt.hash(
            TEST_PASSWORD,
            10
        );

    const user =
        await User.create({
            name,
            email,
            password: hashedPassword,
            role: "USER"
        });

    const token =
        jwt.sign(
            {
                id: user._id.toString(),
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "30m"
            }
        );

    return {
        user,
        token
    };
};


/* ============================================================
   PDF TEST DATA
   ============================================================ */

const createPdfBuffer = () => {

    return Buffer.from(
        "%PDF-1.4\n" +
        "1 0 obj\n" +
        "<< /Type /Catalog >>\n" +
        "endobj\n" +
        "%%EOF"
    );
};


/* ============================================================
   UPLOAD HELPER
   ============================================================ */

const uploadPdf = async (
    token,
    filename = "download-test.pdf"
) => {

    const content =
        createPdfBuffer();

    const response =
        await request(app)
            .post("/api/files/upload")
            .set(
                "Authorization",
                `Bearer ${token}`
            )
            .attach(
                "file",
                content,
                {
                    filename,
                    contentType:
                        "application/pdf"
                }
            );

    assert.equal(
        response.statusCode,
        201,
        `Upload failed: ${JSON.stringify(
            response.body
        )}`
    );

    return {
        response,
        content
    };
};


/* ============================================================
   GET FILE ID
   ============================================================ */

const getFileId = (
    response
) => {

    return (
        response.body?.data?._id ||
        response.body?.data?.id
    );
};


/* ============================================================
   DATABASE SETUP
   ============================================================ */

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    await clearTestDatabase();

    const timestamp =
        Date.now();

    const random =
        Math.random()
            .toString(36)
            .slice(2);

    const first =
        await createTestUser(
            `download-user-1-${timestamp}-${random}@example.com`,
            "Download User One"
        );

    const second =
        await createTestUser(
            `download-user-2-${timestamp}-${random}@example.com`,
            "Download User Two"
        );

    user1 = first.user;
    token1 = first.token;

    user2 = second.user;
    token2 = second.token;

});


after(async () => {

    await stopTestDatabase();

});


/* ============================================================
   1. AUTHENTICATION
   ============================================================ */

test(
    "download requires authentication",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/507f1f77bcf86cd799439011/download"
                );

        assert.equal(
            response.statusCode,
            401
        );

    }
);


/* ============================================================
   2. OWNER DOWNLOAD
   ============================================================ */

test(
    "owner can download their own file",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "owner-download.pdf"
            );

        const fileId =
            getFileId(upload.response);

        assert.ok(
            fileId,
            "Upload response did not contain file ID"
        );

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        assert.deepEqual(
            Buffer.from(
                response.body
            ),
            upload.content
        );

    }
);


/* ============================================================
   3. CONTENT INTEGRITY
   ============================================================ */

test(
    "downloaded file content matches original plaintext",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "content-check.pdf"
            );

        const fileId =
            getFileId(upload.response);

        assert.ok(fileId);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        assert.deepEqual(
            Buffer.from(
                response.body
            ),
            upload.content
        );

    }
);


/* ============================================================
   4. CONTENT TYPE
   ============================================================ */

test(
    "download sets correct Content-Type",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "content-type.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        assert.equal(
            response.headers[
                "content-type"
            ],
            "application/pdf"
        );

    }
);


/* ============================================================
   5. CONTENT DISPOSITION
   ============================================================ */

test(
    "download sets Content-Disposition attachment",
    async () => {

        const filename =
            "private-document.pdf";

        const upload =
            await uploadPdf(
                token1,
                filename
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const disposition =
            response.headers[
                "content-disposition"
            ];

        assert.ok(
            disposition
        );

        assert.match(
            disposition,
            /attachment/i
        );

        assert.match(
            disposition,
            /private-document\.pdf/i
        );

    }
);


/* ============================================================
   6. IDOR PROTECTION
   ============================================================ */

test(
    "USER cannot download another user's file",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "user1-private.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token2}`
                );

        assert.equal(
            response.statusCode,
            403
        );

    }
);


/* ============================================================
   7. OTHER USER CANNOT GET PLAINTEXT
   ============================================================ */

test(
    "another user cannot access plaintext",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "secret.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token2}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            403
        );

    }
);


/* ============================================================
   8. NON-EXISTENT FILE
   ============================================================ */

test(
    "non-existent file returns 404",
    async () => {

        const fakeId =
            "507f1f77bcf86cd799439011";

        const response =
            await request(app)
                .get(
                    `/api/files/${fakeId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                );

        assert.equal(
            response.statusCode,
            404
        );

    }
);


/* ============================================================
   9. INVALID FILE ID
   ============================================================ */

test(
    "invalid MongoDB file ID is handled safely",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files/not-a-valid-id/download"
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                );

        assert.notEqual(
            response.statusCode,
            500
        );

    }
);


/* ============================================================
   10. DATABASE OWNERSHIP
   ============================================================ */

test(
    "file belongs to the authenticated owner",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "ownership.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const file =
            await File.findById(
                fileId
            );

        assert.ok(file);

        assert.equal(
            file.owner.toString(),
            user1._id.toString()
        );

    }
);


/* ============================================================
   11. OWNER IDOR CHECK
   ============================================================ */

test(
    "second user cannot download first user's file",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "idor.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token2}`
                );

        assert.equal(
            response.statusCode,
            403
        );

        const file =
            await File.findById(
                fileId
            );

        assert.equal(
            file.owner.toString(),
            user1._id.toString()
        );

    }
);


/* ============================================================
   12. TWO USERS ISOLATION
   ============================================================ */

test(
    "each user can download only their own file",
    async () => {

        const upload1 =
            await uploadPdf(
                token1,
                "user1.pdf"
            );

        const upload2 =
            await uploadPdf(
                token2,
                "user2.pdf"
            );

        const id1 =
            getFileId(
                upload1.response
            );

        const id2 =
            getFileId(
                upload2.response
            );

        const user1Own =
            await request(app)
                .get(
                    `/api/files/${id1}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        const user2Own =
            await request(app)
                .get(
                    `/api/files/${id2}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token2}`
                )
                .buffer(true);

        assert.equal(
            user1Own.statusCode,
            200
        );

        assert.equal(
            user2Own.statusCode,
            200
        );

        assert.deepEqual(
            Buffer.from(
                user1Own.body
            ),
            upload1.content
        );

        assert.deepEqual(
            Buffer.from(
                user2Own.body
            ),
            upload2.content
        );


        const user1Other =
            await request(app)
                .get(
                    `/api/files/${id2}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                );

        const user2Other =
            await request(app)
                .get(
                    `/api/files/${id1}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token2}`
                );

        assert.equal(
            user1Other.statusCode,
            403
        );

        assert.equal(
            user2Other.statusCode,
            403
        );

    }
);


/* ============================================================
   13. JWT PROTECTION
   ============================================================ */

test(
    "invalid JWT is rejected",
    async () => {

        const fakeId =
            "507f1f77bcf86cd799439011";

        const response =
            await request(app)
                .get(
                    `/api/files/${fakeId}/download`
                )
                .set(
                    "Authorization",
                    "Bearer invalid.jwt.token"
                );

        assert.equal(
            response.statusCode,
            401
        );

    }
);


/* ============================================================
   14. MISSING JWT
   ============================================================ */

test(
    "missing Authorization header is rejected",
    async () => {

        const fakeId =
            "507f1f77bcf86cd799439011";

        const response =
            await request(app)
                .get(
                    `/api/files/${fakeId}/download`
                );

        assert.equal(
            response.statusCode,
            401
        );

    }
);


/* ============================================================
   15. TAMPERED S3 KEY
   ============================================================ */

test(
    "invalid S3 key fails safely",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "tampered-storage.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const file =
            await File.findById(
                fileId
            );

        assert.ok(file);

        file.s3Key =
            `files/${user1._id}/non-existent-file.enc`;

        await file.save();

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                );

        assert.equal(
            response.statusCode,
            500
        );

        assert.notEqual(
            response.body?.message,
            undefined
        );

    }
);


/* ============================================================
   16. TAMPERED IV
   ============================================================ */

test(
    "tampered IV fails integrity/decryption",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "tampered-iv.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const file =
            await File.findById(
                fileId
            );

        assert.ok(file);

        const originalIv =
            file.iv;

        const modifiedIv =
            originalIv
                .split("")
                .map(
                    (char, index) =>
                        index === 0
                            ? char === "a"
                                ? "b"
                                : "a"
                            : char
                )
                .join("");

        file.iv =
            modifiedIv;

        await file.save();

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                );

        assert.equal(
            response.statusCode,
            500
        );

    }
);


/* ============================================================
   17. TAMPERED HASH
   ============================================================ */

test(
    "tampered hash triggers integrity protection",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "tampered-hash.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const file =
            await File.findById(
                fileId
            );

        assert.ok(file);

        file.hash =
            "0".repeat(64);

        await file.save();

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                );

        assert.equal(
            response.statusCode,
            500
        );

        assert.equal(
            response.body?.message,
            "Integrity check failed"
        );

    }
);


/* ============================================================
   18. S3 KEY IS NOT EXPOSED
   ============================================================ */

test(
    "download response does not expose S3 key",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "s3-key-protection.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const file =
            await File.findById(
                fileId
            );

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const body =
            Buffer.from(
                response.body
            ).toString();

        assert.equal(
            body.includes(
                file.s3Key
            ),
            false
        );

    }
);


/* ============================================================
   19. ENCRYPTION KEY IS NOT EXPOSED
   ============================================================ */

test(
    "download response does not expose encryption key",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "encryption-key-protection.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const body =
            Buffer.from(
                response.body
            ).toString();

        assert.equal(
            body.includes(
                process.env.ENCRYPTION_KEY
            ),
            false
        );

    }
);


/* ============================================================
   20. FILE METADATA SECURITY
   ============================================================ */

test(
    "download does not return database metadata as JSON",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "metadata.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        assert.ok(
            Buffer.isBuffer(
                response.body
            )
        );

        assert.equal(
            response.body
                .toString()
                .includes(
                    fileId.toString()
                ),
            false
        );

    }
);


/* ============================================================
   21. DATABASE RECORD REMAINS AFTER DOWNLOAD
   ============================================================ */

test(
    "successful download does not delete database record",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "persistent-file.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const file =
            await File.findById(
                fileId
            );

        assert.ok(
            file,
            "File record should remain after download"
        );

    }
);


/* ============================================================
   22. DOWNLOAD DOES NOT CHANGE FILE OWNER
   ============================================================ */

test(
    "download does not change file ownership",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "owner-preservation.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const before =
            await File.findById(
                fileId
            );

        const originalOwner =
            before.owner.toString();

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const after =
            await File.findById(
                fileId
            );

        assert.equal(
            after.owner.toString(),
            originalOwner
        );

    }
);


/* ============================================================
   23. DOWNLOAD DOES NOT CHANGE HASH
   ============================================================ */

test(
    "successful download does not change stored hash",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "hash-preservation.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const before =
            await File.findById(
                fileId
            );

        const originalHash =
            before.hash;

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const after =
            await File.findById(
                fileId
            );

        assert.equal(
            after.hash,
            originalHash
        );

    }
);


/* ============================================================
   24. DOWNLOAD DOES NOT CHANGE IV
   ============================================================ */

test(
    "successful download does not change IV",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "iv-preservation.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const before =
            await File.findById(
                fileId
            );

        const originalIv =
            before.iv;

        const response =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            response.statusCode,
            200
        );

        const after =
            await File.findById(
                fileId
            );

        assert.equal(
            after.iv,
            originalIv
        );

    }
);


/* ============================================================
   25. FILE DOES NOT BECOME DELETED AFTER DOWNLOAD
   ============================================================ */

test(
    "multiple downloads of same file succeed",
    async () => {

        const upload =
            await uploadPdf(
                token1,
                "multiple-downloads.pdf"
            );

        const fileId =
            getFileId(upload.response);

        const first =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        const second =
            await request(app)
                .get(
                    `/api/files/${fileId}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${token1}`
                )
                .buffer(true);

        assert.equal(
            first.statusCode,
            200
        );

        assert.equal(
            second.statusCode,
            200
        );

        assert.deepEqual(
            Buffer.from(
                first.body
            ),
            Buffer.from(
                second.body
            )
        );

        assert.deepEqual(
            Buffer.from(
                first.body
            ),
            upload.content
        );

    }
);