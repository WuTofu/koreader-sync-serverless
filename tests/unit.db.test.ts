import { describe, expect, it, vi } from "vitest";
import { getDatabaseInitStatus } from "../src/db";
import { D1DatabaseAdapter } from "../src/database/d1Adapter";
import { createMockEnv } from "./helpers/mock-db";

describe("getDatabaseInitStatus", () => {
  it("reports a complete schema with a single sqlite_master query", async () => {
    const env = createMockEnv();
    const prepareSpy = vi.spyOn(env.DB, "prepare");
    const db = new D1DatabaseAdapter(env.DB);

    const status = await getDatabaseInitStatus(db);

    expect(status).toEqual({ initialized: true, missingTables: [] });
    const sqliteMasterCalls = prepareSpy.mock.calls.filter(([sql]) => String(sql).toLowerCase().includes("sqlite_master"));
    expect(sqliteMasterCalls).toHaveLength(1);
  });

  it("reports missing tables from the same single query", async () => {
    // The mock DB's `initialized: false` makes every required table absent from
    // sqlite_master (mirroring an uninitialized D1 database), regardless of which
    // table names are also passed in `missingTables`.
    const env = createMockEnv({ initialized: false, missingTables: ["users", "progress"] });
    const db = new D1DatabaseAdapter(env.DB);

    const status = await getDatabaseInitStatus(db);

    expect(status.initialized).toBe(false);
    expect([...status.missingTables].sort()).toEqual(["progress", "sessions", "statistics_snapshot", "users"]);
  });
});
