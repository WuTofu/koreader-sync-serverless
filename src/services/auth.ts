import { getCookie } from "hono/cookie";
import { findAdminSessionByTokenHash, findUserByUsername, findWebUserBySessionTokenHash, purgeExpiredAdminSessions } from "../db";
import { sha256, timingSafeEqual, verifyPassword } from "../crypto";
import { parsePbkdf2Iterations } from "./common";
import { getCachedUser, putCachedUser, safeWaitUntil } from "./authCache";
import type { AppContext } from "../context";
import type { DatabaseAdapter } from "../database/adapter";
import { resolveDatabaseAdapter } from "../context";

// Throttle the expired-admin-session cleanup so it runs at most once per interval
// instead of on every authAdmin() call. Module-scope, so it's per-isolate: worst case
// each isolate runs it once per interval, which is still a large cut from "every request".
const ADMIN_SESSION_PURGE_INTERVAL_MS = 60 * 60 * 1000;
let lastAdminSessionPurgeAt = 0;

type AppContextWithDb = AppContext & {
  get<K extends "db">(key: K): DatabaseAdapter;
};

function resolveDb(c: AppContextWithDb): DatabaseAdapter {
  return resolveDatabaseAdapter(c);
}

export const USER_SESSION_COOKIE = "ks_session";
export const ADMIN_SESSION_COOKIE = "ks_admin_session";

export function isValidField(field: unknown): field is string {
  return typeof field === "string" && field.length > 0;
}

export function isValidKeyField(field: unknown): field is string {
  return isValidField(field) && !field.includes(":");
}

export { timingSafeEqual } from "../crypto";

export async function authKoreader(c: AppContextWithDb): Promise<{ userId: number; username: string } | null> {
  const username = c.req.header("x-auth-user");
  const password = c.req.header("x-auth-key");
  if (!isValidKeyField(username) || !isValidField(password)) return null;

  let user = await getCachedUser(c.env, username);
  if (user === undefined) {
    user = await findUserByUsername(resolveDb(c), username);
    putCachedUser(c, username, user);
  }
  if (!user) return null;

  const iterations = parsePbkdf2Iterations(c.env);
  const ok = await verifyPassword(password, user.username, c.env.PASSWORD_PEPPER, user.password_hash, iterations);
  if (!ok) return null;
  return { userId: user.id, username: user.username };
}

export async function authWebUser(c: AppContextWithDb): Promise<{ userId: number; username: string } | null> {
  const token = getCookie(c, USER_SESSION_COOKIE);
  if (!token) return null;

  const tokenHash = await sha256(`${token}:${c.env.PASSWORD_PEPPER}`);
  const row = await findWebUserBySessionTokenHash(resolveDb(c), tokenHash);

  if (!row) return null;
  return { userId: row.id, username: row.username };
}

export async function authAdmin(c: AppContextWithDb): Promise<{ mode: "token" } | null> {
  const token = getCookie(c, ADMIN_SESSION_COOKIE);
  if (!token || !c.env.ADMIN_TOKEN) return null;
  const tokenHash = await sha256(`${token}:${c.env.PASSWORD_PEPPER}`);
  const db = resolveDb(c);
  // Best-effort cleanup: throttled to once per ADMIN_SESSION_PURGE_INTERVAL_MS instead
  // of firing a DELETE on every admin request, and routed through waitUntil so it
  // actually completes instead of racing the response.
  const now = Date.now();
  if (now - lastAdminSessionPurgeAt > ADMIN_SESSION_PURGE_INTERVAL_MS) {
    lastAdminSessionPurgeAt = now;
    safeWaitUntil(c, purgeExpiredAdminSessions(db).catch((e) => console.error("[admin] session purge failed:", e)));
  }
  const session = await findAdminSessionByTokenHash(db, tokenHash);
  if (!session) return null;
  return { mode: "token" };
}
