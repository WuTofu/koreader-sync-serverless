// Two-tier cache for the `users` row used by authKoreader (src/services/auth.ts).
// The row returned by findUserByUsername is identical on every request until the
// user's password changes or the account is deleted, so it is safe to cache — the
// PBKDF2 password check still runs on every request, a cache hit can never bypass auth.
//
// Tier 1 (isolate memory): a module-scope Map. Fast, but scoped to a single isolate
// and lost on eviction/redeploy.
// Tier 2 (Cache API / caches.default): scoped to a colo, survives isolate eviction,
// but is INERT on *.workers.dev subdomains and in local dev/playground previews — every
// call is wrapped in try/catch so a dead cache never breaks a request.
//
// Known limitation: invalidation (invalidateCachedUser) only clears the calling
// isolate's memory tier and the calling colo's edge tier. After an admin password
// change, other colos may keep authenticating the OLD password for up to
// AUTH_CACHE_TTL_SECONDS. Keep the default TTL short if that window matters; existing
// session revocation (deleteSessionsByUserId) is unaffected since it's uncached.
import type { AppContext } from "../context";
import { sha256 } from "../crypto";
import type { Env, UserRow } from "../types";

const DEFAULT_AUTH_CACHE_TTL_SECONDS = 300;
const DEFAULT_AUTH_CACHE_NEGATIVE_TTL_SECONDS = 30;
const MEMORY_CACHE_MAX_ENTRIES = 500;
// Cache API keys must be full URLs; this host is never actually requested.
const CACHE_KEY_ORIGIN = "https://auth-cache.koreader-sync.internal";

type CachedEntry = { row: UserRow | null; expiresAt: number };

const memoryCache = new Map<string, CachedEntry>();

export function parseAuthCacheTtlSeconds(env: Env): number {
  const value = Number(env.AUTH_CACHE_TTL_SECONDS ?? DEFAULT_AUTH_CACHE_TTL_SECONDS);
  return Number.isFinite(value) && value >= 0 ? value : DEFAULT_AUTH_CACHE_TTL_SECONDS;
}

export function parseAuthCacheNegativeTtlSeconds(env: Env): number {
  const value = Number(env.AUTH_CACHE_NEGATIVE_TTL_SECONDS ?? DEFAULT_AUTH_CACHE_NEGATIVE_TTL_SECONDS);
  return Number.isFinite(value) && value >= 0 ? value : DEFAULT_AUTH_CACHE_NEGATIVE_TTL_SECONDS;
}

// c.executionCtx throws outside a real Workers fetch handler (e.g. src/node/server.ts
// calls app.fetch(request, env) with no third argument). Fall back to a detached,
// caught promise so cache writes never crash or reject a request.
export function safeWaitUntil(c: AppContext, promise: Promise<unknown>): void {
  try {
    c.executionCtx.waitUntil(promise);
  } catch {
    void promise.catch(() => {});
  }
}

async function cacheKeyFor(env: Env, username: string): Promise<string> {
  // Never put the raw username in a cache key/URL; hash it with the app pepper.
  const digest = await sha256(`${username}:${env.PASSWORD_PEPPER}`);
  return `${CACHE_KEY_ORIGIN}/user/${digest}`;
}

function pruneMemoryCacheIfNeeded(): void {
  if (memoryCache.size < MEMORY_CACHE_MAX_ENTRIES) return;
  const oldestKey = memoryCache.keys().next().value;
  if (oldestKey !== undefined) memoryCache.delete(oldestKey);
}

function readMemory(key: string): UserRow | null | undefined {
  const entry = memoryCache.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt <= Date.now()) {
    memoryCache.delete(key);
    return undefined;
  }
  return entry.row;
}

function writeMemory(key: string, row: UserRow | null, ttlSeconds: number): void {
  if (ttlSeconds <= 0) return;
  pruneMemoryCacheIfNeeded();
  memoryCache.set(key, { row, expiresAt: Date.now() + ttlSeconds * 1000 });
}

function getEdgeCache(): Cache | undefined {
  return (globalThis as { caches?: { default?: Cache } }).caches?.default;
}

async function readEdgeCache(key: string): Promise<UserRow | null | undefined> {
  try {
    const cache = getEdgeCache();
    if (!cache) return undefined;
    const response = await cache.match(key);
    if (!response) return undefined;
    const text = await response.text();
    return text === "null" ? null : (JSON.parse(text) as UserRow);
  } catch {
    return undefined;
  }
}

async function writeEdgeCache(key: string, row: UserRow | null, ttlSeconds: number): Promise<void> {
  if (ttlSeconds <= 0) return;
  try {
    const cache = getEdgeCache();
    if (!cache) return;
    const response = new Response(JSON.stringify(row), {
      headers: {
        "content-type": "application/json",
        // "private" (not "no-store") — the Cache API rejects storing no-store responses.
        "cache-control": `private, max-age=${ttlSeconds}`,
      },
    });
    await cache.put(key, response);
  } catch {
    // Inert on workers.dev / local dev / playground previews — never fail the request.
  }
}

async function deleteEdgeCache(key: string): Promise<void> {
  try {
    const cache = getEdgeCache();
    if (!cache) return;
    await cache.delete(key);
  } catch {
    // ignore
  }
}

function debugLog(env: Env, message: string): void {
  if (env.DEBUG === "true" || env.DEBUG === "1") console.log(`[auth-cache] ${message}`);
}

/** Returns undefined on a cache miss (tier 1 and tier 2 both missed/expired). */
export async function getCachedUser(env: Env, username: string): Promise<UserRow | null | undefined> {
  const key = await cacheKeyFor(env, username);

  const memoryHit = readMemory(key);
  if (memoryHit !== undefined) {
    debugLog(env, `tier1 hit (memory, ${memoryCache.size} entries)`);
    return memoryHit;
  }

  const edgeHit = await readEdgeCache(key);
  if (edgeHit !== undefined) {
    debugLog(env, "tier2 hit (edge cache), backfilling tier1");
    // Backfill tier 1. The Cache API doesn't expose remaining max-age, so refill with
    // the configured TTL rather than the edge entry's true remaining lifetime.
    const ttl = edgeHit === null ? parseAuthCacheNegativeTtlSeconds(env) : parseAuthCacheTtlSeconds(env);
    writeMemory(key, edgeHit, ttl);
    return edgeHit;
  }

  debugLog(env, "miss (tier1 + tier2), falling through to D1");
  return undefined;
}

/** Fire-and-forget: stores `row` (or `null` for a negative/unknown-username entry). */
export function putCachedUser(c: AppContext, username: string, row: UserRow | null): void {
  const env = c.env;
  const ttlSeconds = row === null ? parseAuthCacheNegativeTtlSeconds(env) : parseAuthCacheTtlSeconds(env);
  if (ttlSeconds <= 0) return;
  safeWaitUntil(
    c,
    (async () => {
      const key = await cacheKeyFor(env, username);
      writeMemory(key, row, ttlSeconds);
      await writeEdgeCache(key, row, ttlSeconds);
      debugLog(env, `wrote tier1+tier2 (ttl=${ttlSeconds}s, ${row === null ? "negative" : "positive"})`);
    })()
  );
}

/** Fire-and-forget: clears both tiers for `username` after users-table mutations. */
export function invalidateCachedUser(c: AppContext, username: string): void {
  const env = c.env;
  safeWaitUntil(
    c,
    (async () => {
      const key = await cacheKeyFor(env, username);
      memoryCache.delete(key);
      await deleteEdgeCache(key);
      debugLog(env, "invalidated tier1+tier2");
    })()
  );
}
