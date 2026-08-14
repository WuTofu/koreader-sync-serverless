import { describe, expect, it, vi } from "vitest";
import app from "../src/index";
import { createMockEnv } from "./helpers/mock-db";
import { getCookieHeaderFromResponse } from "./helpers/http";

describe("authAdmin session purge throttling", () => {
  it("purges expired admin sessions at most once across repeated requests", async () => {
    const env = createMockEnv();

    const loginRes = await app.request(
      "/admin/auth/login",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: env.ADMIN_TOKEN }) },
      env
    );
    expect(loginRes.status).toBe(200);
    const adminCookie = getCookieHeaderFromResponse(loginRes, "ks_admin_session");

    const prepareSpy = vi.spyOn(env.DB, "prepare");

    for (let i = 0; i < 3; i++) {
      const res = await app.request("/admin/me", { method: "GET", headers: { cookie: adminCookie } }, env);
      expect(res.status).toBe(200);
    }

    const purgeCalls = prepareSpy.mock.calls.filter(([sql]) =>
      String(sql).toLowerCase().startsWith("delete from admin_sessions where expires_at")
    );
    expect(purgeCalls).toHaveLength(1);
  });
});
