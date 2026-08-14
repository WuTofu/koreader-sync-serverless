import { describe, expect, it, vi } from "vitest";
import { md5 } from "js-md5";
import app from "../src/index";
import { hashPassword } from "../src/crypto";
import { parsePbkdf2Iterations } from "../src/services/common";
import { createMockEnv } from "./helpers/mock-db";
import { getCookieHeaderFromResponse } from "./helpers/http";

const PASSWORD = "password";
const MD5_PASSWORD = md5(PASSWORD);

async function seedUser(env: ReturnType<typeof createMockEnv>, username: string, mdPassword: string) {
  const hashed = await hashPassword(mdPassword, username, env.PASSWORD_PEPPER, parsePbkdf2Iterations(env));
  await env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(username, hashed).run();
}

function countUserLookups(spy: ReturnType<typeof vi.spyOn>): number {
  return spy.mock.calls.filter(([sql]) =>
    String(sql).toLowerCase().includes("select id, username, password_hash from users")
  ).length;
}

// The cache write is fired via safeWaitUntil (executionCtx.waitUntil, or a detached
// promise when no ExecutionContext is available, as in these tests). Give it a tick
// to settle before asserting on cache state.
async function flush() {
  await new Promise((resolve) => setTimeout(resolve, 10));
}

describe("authKoreader cache", () => {
  it("serves the second lookup from cache after a D1 miss", async () => {
    const env = createMockEnv();
    await seedUser(env, "alice", MD5_PASSWORD);
    const prepareSpy = vi.spyOn(env.DB, "prepare");

    const first = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "alice", "x-auth-key": MD5_PASSWORD } },
      env
    );
    expect(first.status).toBe(200);
    await flush();
    expect(countUserLookups(prepareSpy)).toBe(1);

    const second = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "alice", "x-auth-key": MD5_PASSWORD } },
      env
    );
    expect(second.status).toBe(200);
    expect(countUserLookups(prepareSpy)).toBe(1); // no additional D1 read
  });

  it("rejects a wrong password even when the user row is cached", async () => {
    const env = createMockEnv();
    await seedUser(env, "bob", MD5_PASSWORD);

    await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "bob", "x-auth-key": MD5_PASSWORD } },
      env
    );
    await flush();

    const wrong = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "bob", "x-auth-key": "not-the-password" } },
      env
    );
    expect(wrong.status).toBe(401);
  });

  it("caches unknown usernames as a negative entry", async () => {
    const env = createMockEnv();
    const prepareSpy = vi.spyOn(env.DB, "prepare");

    const first = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "ghost", "x-auth-key": "whatever" } },
      env
    );
    expect(first.status).toBe(401);
    await flush();
    expect(countUserLookups(prepareSpy)).toBe(1);

    const second = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "ghost", "x-auth-key": "whatever" } },
      env
    );
    expect(second.status).toBe(401);
    expect(countUserLookups(prepareSpy)).toBe(1); // still just the one D1 read
  });

  it("re-reads from D1 once the cache TTL expires", async () => {
    const env = createMockEnv();
    env.AUTH_CACHE_TTL_SECONDS = "1";
    await seedUser(env, "carol", MD5_PASSWORD);
    const prepareSpy = vi.spyOn(env.DB, "prepare");

    await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "carol", "x-auth-key": MD5_PASSWORD } },
      env
    );
    await flush();
    expect(countUserLookups(prepareSpy)).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 1100));

    await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "carol", "x-auth-key": MD5_PASSWORD } },
      env
    );
    expect(countUserLookups(prepareSpy)).toBe(2);
  }, 5000);

  it("invalidates the cache when an admin changes a user's password", async () => {
    const env = createMockEnv();
    await seedUser(env, "dave", MD5_PASSWORD);

    // Warm the cache with the old password.
    const warm = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "dave", "x-auth-key": MD5_PASSWORD } },
      env
    );
    expect(warm.status).toBe(200);
    await flush();

    const loginRes = await app.request(
      "/admin/auth/login",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: env.ADMIN_TOKEN }) },
      env
    );
    const adminCookie = getCookieHeaderFromResponse(loginRes, "ks_admin_session");

    const usersRes = await app.request("/admin/users", { method: "GET", headers: { cookie: adminCookie } }, env);
    const { items } = await usersRes.json<{ items: Array<{ id: number; username: string }> }>();
    const dave = items.find((u) => u.username === "dave")!;

    const newMd5Password = md5("brand-new-password");
    const changeRes = await app.request(
      `/admin/users/${dave.id}/password`,
      {
        method: "PUT",
        headers: { "content-type": "application/json", cookie: adminCookie },
        body: JSON.stringify({ password: "brand-new-password" }),
      },
      env
    );
    expect(changeRes.status).toBe(200);
    await flush();

    const oldPasswordRes = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "dave", "x-auth-key": MD5_PASSWORD } },
      env
    );
    expect(oldPasswordRes.status).toBe(401);

    const newPasswordRes = await app.request(
      "/users/auth",
      { method: "GET", headers: { "x-auth-user": "dave", "x-auth-key": newMd5Password } },
      env
    );
    expect(newPasswordRes.status).toBe(200);
  });
});
