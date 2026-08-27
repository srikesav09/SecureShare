import "./env.js";

import test, { before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";

import app from "../src/app.js";

import User from "../src/models/user.model.js";
import File from "../src/models/file.model.js";
import Share from "../src/models/share.model.js";

import {
    startTestDatabase,
    clearTestDatabase,
    stopTestDatabase
} from "./setup.js";


const API = "/api";

let owner;
let attacker;

let ownerToken;
let attackerToken;

let ownerFile;
let attackerFile;

let ownerShare;


const uniqueEmail = (prefix) =>
    `${prefix}-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 8)}@example.com`;


async function registerAndLogin(name, email) {

    const password = "Password@123";

    // Give every test account a unique client IP.
    // This prevents the production login rate limiter
    // from affecting the security test suite.
    const testIp =
        `10.70.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

    // --------------------------------------------------------
    // REGISTER
    // --------------------------------------------------------

    const register = await request(app)
        .post(`${API}/auth/register`)
        .set("X-Forwarded-For", testIp)
        .send({
            name,
            email,
            password
        });

    assert.ok(
        [200, 201].includes(register.status),
        `Registration failed: ${JSON.stringify(register.body)}`
    );

    // --------------------------------------------------------
    // LOGIN
    // --------------------------------------------------------

    const login = await request(app)
        .post(`${API}/auth/login`)
        .set("X-Forwarded-For", testIp)
        .send({
            email,
            password
        });

    assert.equal(
        login.status,
        200,
        `Login failed: ${JSON.stringify(login.body)}`
    );

    // --------------------------------------------------------
    // TOKEN
    // --------------------------------------------------------

    const token =
        login.body?.data?.token ||
        login.body?.token ||
        login.body?.data?.accessToken ||
        login.body?.accessToken;

    assert.ok(
        token,
        `No access token returned: ${JSON.stringify(login.body)}`
    );

    // --------------------------------------------------------
    // DATABASE USER
    // --------------------------------------------------------

    const user =
        await User.findOne({
            email
        });

    assert.ok(
        user,
        `User was not found in database: ${email}`
    );

    return {
        token,
        user
    };
}


/*
 * Create a valid File document directly in MongoDB.
 *
 * This avoids S3/upload behaviour because this test
 * is specifically testing parameter pollution.
 */
async function createTestFile(user, suffix) {

    const userId = user._id;

    assert.ok(
        userId,
        "Test user does not have a MongoDB _id"
    );


    return File.create({

        originalName:
            `${suffix}.txt`,

        storedName:
            `${suffix}-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}.txt`,

        mimeType:
            "text/plain",

        size:
            10,

        s3Key:
            `test/${userId}/${suffix}-${Date.now()}-${Math.random()
                .toString(36)
                .slice(2, 8)}`,

        /*
         * THIS is the important fix.
         */
        owner:
            userId,

        encrypted:
            true,

        iv:
            "test-iv",

        hash:
            "test-hash"
    });
}


before(async () => {

    await startTestDatabase();

});


beforeEach(async () => {

    await clearTestDatabase();


    /*
     * OWNER
     */
    const ownerResult =
        await registerAndLogin(
            "Pollution Owner",
            uniqueEmail("owner")
        );

    ownerToken =
        ownerResult.token;

    owner =
        ownerResult.user;


    /*
     * ATTACKER
     */
    const attackerResult =
        await registerAndLogin(
            "Pollution Attacker",
            uniqueEmail("attacker")
        );

    attackerToken =
        attackerResult.token;

    attacker =
        attackerResult.user;


    /*
     * Create files.
     */
    ownerFile =
        await createTestFile(
            owner,
            "owner-file"
        );


    attackerFile =
        await createTestFile(
            attacker,
            "attacker-file"
        );


    /*
     * Create owner's share.
     */
    ownerShare =
        await Share.create({

            file:
                ownerFile._id,

            owner:
                owner._id,

            token:
                `hashed-pollution-${Date.now()}-${Math.random()
                    .toString(36)
                    .slice(2, 8)}`,

            expiresAt:
                new Date(
                    Date.now() +
                    60 * 60 * 1000
                ),

            isRevoked:
                false,

            downloadCount:
                0,

            maxDownloads:
                null,

            passwordHash:
                null
        });

});


after(async () => {

    await stopTestDatabase();

});


/*
 * =========================================================
 * FILE DELETE
 * =========================================================
 */

test(
    "duplicate query parameters cannot bypass file ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?id=${attackerFile._id}&id=${ownerFile._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        const file =
            await File.findById(
                ownerFile._id
            );


        assert.ok(
            file,
            "Owner file was unexpectedly deleted"
        );
    }
);


/*
 * =========================================================
 * USER ID POLLUTION
 * =========================================================
 */

test(
    "userId query parameter cannot replace JWT identity",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?userId=${owner._id}&userId=${attacker._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                ownerFile._id
            )
        );
    }
);


/*
 * =========================================================
 * OWNER ID POLLUTION
 * =========================================================
 */

test(
    "ownerId query parameter cannot change authenticated ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?ownerId=${owner._id}&ownerId=${attacker._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                ownerFile._id
            )
        );
    }
);


/*
 * =========================================================
 * ATTACKER FIRST
 * =========================================================
 */

test(
    "attacker-first duplicate parameters cannot change resource ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?userId=${attacker._id}&userId=${owner._id}&ownerId=${attacker._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                ownerFile._id
            )
        );
    }
);


/*
 * =========================================================
 * ARRAY PARAMETER
 * =========================================================
 */

test(
    "array-style file ID parameter cannot bypass authorization",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?id[]=${attackerFile._id}&id[]=${ownerFile._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                ownerFile._id
            )
        );
    }
);


/*
 * =========================================================
 * MIXED IDENTITY PARAMETERS
 * =========================================================
 */

test(
    "mixed identity parameters cannot override JWT identity",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?userId=${owner._id}&ownerId=${owner._id}&user=${owner._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        assert.ok(
            await File.findById(
                ownerFile._id
            )
        );
    }
);


/*
 * =========================================================
 * SHARE REVOCATION
 * =========================================================
 */

test(
    "duplicate share ID parameters cannot bypass ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${ownerShare._id}?shareId=${ownerShare._id}&shareId=attacker`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.equal(
            response.status,
            403
        );


        const share =
            await Share.findById(
                ownerShare._id
            );


        assert.equal(
            share.isRevoked,
            false
        );
    }
);


/*
 * =========================================================
 * SHARE OWNER ID POLLUTION
 * =========================================================
 */

test(
    "share ownerId pollution cannot bypass ownership",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/share/${ownerShare._id}?ownerId=${owner._id}&ownerId=${attacker._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.equal(
            response.status,
            403
        );


        const share =
            await Share.findById(
                ownerShare._id
            );


        assert.equal(
            share.isRevoked,
            false
        );
    }
);


/*
 * =========================================================
 * GET CANNOT REVOKE
 * =========================================================
 */

test(
    "GET with duplicate share parameters cannot revoke a share",
    async () => {

        const response =
            await request(app)
                .get(
                    `/api/share/${ownerShare._id}?shareId=${ownerShare._id}&shareId=attacker`
                )
                .set(
                    "Authorization",
                    `Bearer ${ownerToken}`
                );


        const share =
            await Share.findById(
                ownerShare._id
            );


        assert.equal(
            share.isRevoked,
            false
        );


        assert.notEqual(
            response.status,
            200
        );
    }
);


/*
 * =========================================================
 * PATH PARAMETER CANNOT BE OVERRIDDEN
 * =========================================================
 */

test(
    "path resource ID remains authoritative over query parameters",
    async () => {

        const response =
            await request(app)
                .delete(
                    `/api/files/${ownerFile._id}?id=${attackerFile._id}`
                )
                .set(
                    "Authorization",
                    `Bearer ${attackerToken}`
                );


        assert.notEqual(
            response.status,
            200
        );


        const ownerStillExists =
            await File.findById(
                ownerFile._id
            );


        const attackerStillExists =
            await File.findById(
                attackerFile._id
            );


        assert.ok(
            ownerStillExists,
            "Owner file was deleted"
        );


        assert.ok(
            attackerStillExists,
            "Attacker file was unexpectedly deleted"
        );
    }
);