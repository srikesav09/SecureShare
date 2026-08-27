import "./env.js";

import test, {
    before,
    after
} from "node:test";

import assert from "node:assert/strict";
import request from "supertest";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";

const PASSWORD =
    "AuthorizationEdge123!";

let owner;
let attacker;
let ownerToken;
let attackerToken;
let ownerFile;
let attackerFile;

const registerAndLogin = async (
    name,
    prefix
) => {

    const email =
        `${prefix}-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 10)}@example.com`;

    const register =
        await request(app)
            .post("/api/auth/register")
            .send({
                name,
                email,
                password: PASSWORD
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
                password: PASSWORD
            });

    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );

    const token =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.data?.accessToken ||
        login.body?.accessToken;

    assert.ok(
        token,
        "JWT token missing"
    );

    const user =
        await User.findOne({
            email
        });

    assert.ok(
        user,
        `User not found: ${email}`
    );

    return {
        user,
        token
    };
};

const createFile = async (
    ownerId,
    name
) => {

    return File.create({

        originalName:
            name,

        storedName:
            `${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 10)}.txt`,

        mimeType:
            "text/plain",

        size:
            100,

        s3Key:
            `test/auth-edge-${Date.now()}-${Math.random()
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

before(async () => {

    await startTestDatabase();

    await clearTestDatabase();

    const ownerResult =
        await registerAndLogin(
            "Authorization Owner",
            "auth-owner"
        );

    owner =
        ownerResult.user;

    ownerToken =
        ownerResult.token;

    const attackerResult =
        await registerAndLogin(
            "Authorization Attacker",
            "auth-attacker"
        );

    attacker =
        attackerResult.user;

    attackerToken =
        attackerResult.token;

    ownerFile =
        await createFile(
            owner.id,
            "owner-file.txt"
        );

    attackerFile =
        await createFile(
            attacker.id,
            "attacker-file.txt"
        );
});

after(async () => {

    await stopTestDatabase();

});


test(
    "owner identity matches stored file ownership",
    async () => {

        const databaseFile =
            await File.findById(
                ownerFile.id
            );

        assert.ok(
            databaseFile
        );

        assert.equal(
            String(databaseFile.owner),
            String(owner.id)
        );
    }
);


test(
    "attacker cannot delete owner file",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );

        assert.equal(
            response.status,
            403
        );

        assert.ok(
            await File.findById(
                ownerFile.id
            )
        );
    }
);


test(
    "attacker cannot download owner file",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/files/${ownerFile.id}/download`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );

        assert.ok(
            [403, 404].includes(
                response.status
            )
        );
    }
);


test(
    "query userId cannot switch authenticated identity",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile.id}?userId=${owner.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );

        assert.equal(
            response.status,
            403
        );

        assert.ok(
            await File.findById(
                ownerFile.id
            )
        );
    }
);


test(
    "body userId cannot switch authenticated identity",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                )
                .send({
                    userId:
                        owner.id,

                    owner:
                        owner.id
                });

        assert.equal(
            response.status,
            403
        );

        assert.ok(
            await File.findById(
                ownerFile.id
            )
        );
    }
);


test(
    "X-User-ID cannot replace JWT identity",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                )
                .set(
                    "X-User-ID",
                    String(owner.id)
                );

        assert.equal(
            response.status,
            403
        );

        assert.ok(
            await File.findById(
                ownerFile.id
            )
        );
    }
);


test(
    "X-Owner-ID cannot override authenticated identity",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                )
                .set(
                    "X-Owner-ID",
                    String(owner.id)
                );

        assert.equal(
            response.status,
            403
        );

        assert.ok(
            await File.findById(
                ownerFile.id
            )
        );
    }
);


test(
    "authenticated user can access their own file record",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files"
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );

        assert.equal(
            response.status,
            200
        );

        const body =
            JSON.stringify(
                response.body
            );

        assert.ok(
            body.includes(
                "attacker-file.txt"
            ),
            "Authenticated user's own file was not returned"
        );

        assert.equal(
            body.includes(
                "owner-file.txt"
            ),
            false,
            "Another user's file was exposed"
        );
    }
);


test(
    "user file listing does not expose another user's file",
    async () => {

        const response =
            await request(app)
                .get(
                    "/api/files"
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );

        assert.equal(
            response.status,
            200
        );

        const body =
            JSON.stringify(
                response.body
            );

        assert.ok(
            body.includes(
                "owner-file.txt"
            ),
            "Authenticated owner's file was not returned"
        );

        assert.equal(
            body.includes(
                "attacker-file.txt"
            ),
            false,
            "Owner received another user's file"
        );
    }
);


test(
    "authorization manipulation cannot alter stored ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile.id}?ownerId=${attacker.id}&userId=${attacker.id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                )
                .send({
                    owner:
                        attacker.id,

                    userId:
                        attacker.id
                });

        assert.equal(
            response.status,
            200
        );

        const deleted =
            await File.findById(
                ownerFile.id
            );

        assert.equal(
            deleted,
            null
        );

        const attackerStillExists =
            await File.findById(
                attackerFile.id
            );

        assert.ok(
            attackerStillExists,
            "Attacker's file was unexpectedly modified"
        );

        assert.equal(
            String(attackerStillExists.owner),
            String(attacker.id)
        );
    }
);