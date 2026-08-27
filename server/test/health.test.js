import test, { before, after } from "node:test";
import assert from "node:assert";
import request from "supertest";

import app from "../src/app.js";

test("GET /api/health should return 200", async () => {
  const response = await request(app)
    .get("/api/health");

  assert.strictEqual(response.status, 200);

  assert.strictEqual(
    response.body.success,
    true
  );

  assert.strictEqual(
    response.body.message,
    "SecureShare API is running"
  );

  assert.strictEqual(
    response.body.version,
    "1.0.0"
  );
});