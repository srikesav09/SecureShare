import "./env.js";

import test, {
    before,
    after,
    beforeEach
} from "node:test";

import assert from "node:assert/strict";
import request from "supertest";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";
import AuditLog from "../src/models/audit.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const PASSWORD =
    "DeleteRaceSecurity123!";

let user;
let token;
let file;


/* =========================================================
   HELPERS
   ========================================================= */

const registerAndLogin = async () => {

    const email =
        `delete-race-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;


    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name:
                    "Delete Race User",

                email,

                password:
                    PASSWORD
            });


    assert.equal(
        register.status,
        201,
        `Registration failed: ${JSON.stringify(register.body)}`
    );


    const login =
        await request(app)
            .post("/api/auth/login")
            .send({
                email,

                password:
                    PASSWORD
            });


    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );


    const accessToken =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.accessToken ||
        login.body?.data?.accessToken;


    assert.ok(
        accessToken,
        `JWT token missing: ${JSON.stringify(login.body)}`
    );


    const databaseUser =
        await User.findOne({
            email
        });


    assert.ok(
        databaseUser
    );


    return {
        user:
            databaseUser,

        token:
            accessToken
    };
};


/* =========================================================
   CREATE FILE
   ========================================================= */

const createTestFile = async (
    ownerId,
    suffix = "race"
) => {

    return File.create({

        originalName:
            `${suffix}.txt`,

        storedName:
            `${suffix}-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/delete-race-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.enc`,

        owner:
            ownerId,

        encrypted:
            true,

        iv:
            "test-iv",

        hash:
            "test-hash"

    });
};


/* =========================================================
   SETUP
   ========================================================= */

before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    /*
     * Authenticate once for each test.
     *
     * There is only one login per test and no nested
     * login calls inside the actual test logic.
     */

    await clearTestDatabase();


    const result =
        await registerAndLogin();


    user =
        result.user;

    token =
        result.token;


    file =
        await createTestFile(
            user.id
        );

});


after(async () => {

    await stopTestDatabase();

});


/* =========================================================
   1. TWO SIMULTANEOUS DELETES
   ========================================================= */

test(
    "two simultaneous delete requests cannot both succeed",
    async () => {

        const requests = [
            request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                ),

            request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
        ];


        const responses =
            await Promise.all(
                requests
            );


        const successful =
            responses.filter(
                response =>
                    response.status === 200
            );


        assert.ok(
            successful.length <= 1,
            `Expected at most one successful deletion, got ${successful.length}`
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.equal(
            databaseFile,
            null,
            "File still exists after concurrent successful deletion"
        );

    }
);


/* =========================================================
   2. TEN SIMULTANEOUS DELETES
   ========================================================= */

test(
    "many concurrent deletes leave the file in a consistent state",
    async () => {

        const requests =
            Array.from(
                {
                    length: 10
                },
                () =>
                    request(app)
                        .delete(
                            `/api/files/${file.id}`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            );


        const responses =
            await Promise.all(
                requests
            );


        const successful =
            responses.filter(
                response =>
                    response.status === 200
            );


        assert.ok(
            successful.length <= 1,
            `Multiple delete requests succeeded: ${successful.length}`
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.equal(
            databaseFile,
            null,
            "Concurrent deletion left a file record behind"
        );

    }
);


/* =========================================================
   3. DELETE AFTER CONCURRENT DELETE
   ========================================================= */

test(
    "delete after a concurrent deletion returns not found",
    async () => {

        await Promise.all([
            request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                ),

            request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                )
        ]);


        const response =
            await request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            404,
            `Expected 404 after deletion, got ${response.status}`
        );

    }
);


/* =========================================================
   4. FILE CANNOT REAPPEAR
   ========================================================= */

test(
    "deleted file cannot reappear after concurrent requests",
    async () => {

        await Promise.all(
            Array.from(
                {
                    length: 10
                },
                () =>
                    request(app)
                        .delete(
                            `/api/files/${file.id}`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            )
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.equal(
            databaseFile,
            null
        );

    }
);


/* =========================================================
   5. AUDIT LOG CONSISTENCY
   ========================================================= */

test(
    "concurrent deletion does not create multiple successful delete audits",
    async () => {

        await Promise.all(
            Array.from(
                {
                    length: 10
                },
                () =>
                    request(app)
                        .delete(
                            `/api/files/${file.id}`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            )
        );


        const logs =
            await AuditLog.find({
                resourceId:
                    file.id,

                user:
                    user.id
            });


        const successfulLogs =
            logs.filter(
                log =>
                    log.status === "SUCCESS"
            );


        assert.ok(
            successfulLogs.length <= 1,
            `Multiple successful deletion audit logs were created: ${successfulLogs.length}`
        );

    }
);


/* =========================================================
   6. FILE OWNER IS NOT CHANGED
   ========================================================= */

test(
    "concurrent deletion cannot change file ownership",
    async () => {

        const originalOwner =
            String(file.owner);


        await Promise.all(
            Array.from(
                {
                    length: 5
                },
                () =>
                    request(app)
                        .delete(
                            `/api/files/${file.id}`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            )
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        /*
         * If the record is still present, its owner must
         * remain unchanged.
         */
        if (databaseFile) {

            assert.equal(
                String(databaseFile.owner),
                originalOwner
            );

        }

    }
);


/* =========================================================
   7. OTHER FILE IS NOT DELETED
   ========================================================= */

test(
    "concurrent deletion of one file cannot delete another file",
    async () => {

        const secondFile =
            await createTestFile(
                user.id,
                "second"
            );


        await Promise.all(
            Array.from(
                {
                    length: 10
                },
                () =>
                    request(app)
                        .delete(
                            `/api/files/${file.id}`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            )
        );


        const remainingFile =
            await File.findById(
                secondFile.id
            );


        assert.ok(
            remainingFile,
            "Concurrent deletion removed another file"
        );


        assert.equal(
            String(remainingFile.owner),
            String(user.id)
        );

    }
);


/* =========================================================
   8. DELETE REQUESTS DO NOT CREATE DUPLICATE RECORDS
   ========================================================= */

test(
    "concurrent deletion cannot create duplicate file records",
    async () => {

        await Promise.all(
            Array.from(
                {
                    length: 10
                },
                () =>
                    request(app)
                        .delete(
                            `/api/files/${file.id}`
                        )
                        .set(
                            "Authorization",
                            `Bearer ${token}`
                        )
            )
        );


        const records =
            await File.find({
                _id:
                    file.id
            });


        assert.equal(
            records.length,
            0
        );

    }
);


/* =========================================================
   9. INVALID CONCURRENT DELETE IDS
   ========================================================= */

test(
    "concurrent invalid deletion requests do not crash the server",
    async () => {

        const ids = [
            "not-an-id",
            "invalid",
            "000000000000000000000000",
            "ffffffffffffffffffffffff",
            "123"
        ];


        const responses =
            await Promise.all(
                ids.map(
                    id =>
                        request(app)
                            .delete(
                                `/api/files/${id}`
                            )
                            .set(
                                "Authorization",
                                `Bearer ${token}`
                            )
                )
            );


        for (
            const response
            of responses
        ) {

            assert.notEqual(
                response.status,
                500,
                "Invalid concurrent ID caused a server error"
            );

        }

    }
);


/* =========================================================
   10. NORMAL DELETE STILL WORKS
   ========================================================= */

test(
    "normal deletion remains successful after race-condition coverage",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${file.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${token}`
                );


        assert.equal(
            response.status,
            200,
            `Normal deletion failed: ${JSON.stringify(response.body)}`
        );


        const databaseFile =
            await File.findById(
                file.id
            );


        assert.equal(
            databaseFile,
            null
        );

    }
);