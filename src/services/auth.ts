import { getCookie, setCookie } from "hono/cookie";
import { findAdminSessionByTokenHash, findUserByUsername, findWebUserBySessionTokenHash, purgeExpiredAdminSessions, renewSession } from "../db";
import { sha256, timingSafeEqual, verifyPassword } from "../crypto";
import { parsePbkdf2Iterations, parseSessionRenewWindowHours, parseSessionTtlHours } from "./common";
import { getCachedUser, putCachedUser } from "./authCache";
import type { AppContext } from "../context";
import type { DatabaseAdapter } from "../database/adapter";
import { resolveDatabaseAdapter } from "../context";

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

  const db = resolveDb(c);
  const tokenHash = await sha256(`${token}:${c.env.PASSWORD_PEPPER}`);
  const row = await findWebUserBySessionTokenHash(db, tokenHash);

  if (!row) return null;
  await maybeRenewSession(c, db, token, tokenHash, row.expires_at);
  return { userId: row.id, username: row.username };
}

// Sliding session: extend the stored expiry and refresh the cookie when the session is close
// to lapsing. Only writes when a renewal is actually due, so the common case stays read-only.
async function maybeRenewSession(
  c: AppContextWithDb,
  db: DatabaseAdapter,
  token: string,
  tokenHash: string,
  currentExpiresAt: number
): Promise<void> {
  const ttlHours = parseSessionTtlHours(c.env);
  const windowHours = parseSessionRenewWindowHours(c.env);
  if (windowHours <= 0) return;

  const nowSeconds = Math.floor(Date.now() / 1000);
  const threshold = nowSeconds + windowHours * 3600;
  if (currentExpiresAt > threshold) return;

  const nextExpiresAt = nowSeconds + ttlHours * 3600;
  await renewSession(db, tokenHash, nextExpiresAt);
  setCookie(c, USER_SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: ttlHours * 3600,
  });
}

export async function authAdmin(c: AppContextWithDb): Promise<{ mode: "token" } | null> {
  const token = getCookie(c, ADMIN_SESSION_COOKIE);
  if (!token || !c.env.ADMIN_TOKEN) return null;
  const tokenHash = await sha256(`${token}:${c.env.PASSWORD_PEPPER}`);
  const db = resolveDb(c);
  // Best-effort cleanup: expired sessions are small and infrequent, so purge
  // opportunistically on each auth check without blocking the response.
  void purgeExpiredAdminSessions(db).catch((e) => console.error("[admin] session purge failed:", e));
  const session = await findAdminSessionByTokenHash(db, tokenHash);
  if (!session) return null;
  return { mode: "token" };
}
