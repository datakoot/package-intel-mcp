/**
 * Package Intel MCP — Datakoot
 * Keyless Model Context Protocol server giving AI agents live package intelligence
 * across npm, PyPI, and crates.io: metadata, versions, popularity, dependencies,
 * known advisories, and a composite "health" signal for install decisions.
 *
 * Data sources (all public, keyless, metadata-only):
 *   - npm registry            https://registry.npmjs.org
 *   - npm downloads           https://api.npmjs.org
 *   - PyPI JSON API           https://pypi.org/pypi
 *   - crates.io API           https://crates.io/api/v1
 *   - deps.dev (Google OSI)   https://api.deps.dev/v3   (deps + advisories, cross-ecosystem)
 *
 * Cloudflare Worker (module). Bindings: KV "RL" (licence-key cache), D1 "QUOTA_DB" (call counter).
 */

const POLAR_ORG = "7f455043-0b15-4a1c-b7a0-9c06c9f3b95e";
const CHECKOUT = "https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf";
const FREE_LIMIT = 100;          // anonymous, keyless, per UTC day
const PRO_INCLUDED = 10000;      // calls included in Pro each month
const OVERAGE_PER = 1000;        // then $5 per 1,000
const UA = "Datakoot-Package-Intel/1.0 (+https://datakoot.com; contact@datakoot.com)";
const SERVER = { name: "package-intel", version: "2.0.0" };
const ECO = { npm: "npm", pypi: "pypi", cargo: "cargo", crates: "cargo", pip: "pypi" }; // aliases -> deps.dev system

/* ------------------------------------------------------------------ helpers */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, mcp-protocol-version",
};
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...CORS, ...extra } });

async function getJSON(url, { ttl = 3600 } = {}) {
  const r = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/json" }, cf: { cacheTtl: ttl, cacheEverything: true } });
  if (r.status === 404) return { _notfound: true };
  if (!r.ok) return { _error: `upstream ${r.status}` };
  try { return await r.json(); } catch { return { _error: "bad json from upstream" }; }
}

function normEco(input) {
  const k = String(input || "").toLowerCase().trim();
  return ECO[k] || null;
}

/* ----------------------------------------------------- quota: D1 (atomic) */
/**
 * The free-tier counter used to live in KV. KV caches reads at the edge and is
 * eventually consistent, so a read-modify-write counter loses increments under
 * any real concurrency — measured against production on 2026-08-29: seven
 * consecutive calls moved the counter by three, and once moved it backwards.
 *
 * The counter now lives in D1 (SQLite). One INSERT ... ON CONFLICT DO UPDATE
 * ... RETURNING statement reads, increments and returns the new value inside a
 * single transaction, so there is no window between the read and the write and
 * no increment can be lost. Verified against production on security-intel:
 * 731 calls fired, 731 counted, and every call past 100 refused.
 *
 * Database "datakoot-quota", binding QUOTA_DB:
 *   CREATE TABLE quota (k TEXT PRIMARY KEY, period TEXT NOT NULL,
 *                       n INTEGER NOT NULL, updated INTEGER NOT NULL DEFAULT 0);
 *   CREATE INDEX quota_period ON quota(period);
 * One row per caller, reused across periods, so the table grows with the number
 * of distinct callers rather than with time.
 */
const BUMP_SQL =
  "INSERT INTO quota (k, period, n, updated) VALUES (?1, ?2, 1, ?3) " +
  "ON CONFLICT(k) DO UPDATE SET " +
  "n = CASE WHEN quota.period = excluded.period THEN quota.n + 1 ELSE 1 END, " +
  "period = excluded.period, updated = excluded.updated " +
  "RETURNING n";

/** Count this call and return the caller's running total for the period. */
async function bump(env, k, period) {
  const row = await env.QUOTA_DB.prepare(BUMP_SQL)
    .bind(k, period, Math.floor(Date.now() / 1000))
    .first();
  const n = row && row.n;
  if (typeof n !== "number") throw new Error("quota: no row returned");
    await dkDaily(env, k, period);
  return n;
}

/* Identify a caller without storing an identity.
 *
 * This is an HMAC, not a plain hash, and the key is a 256-bit secret held only
 * in the Worker's environment (IP_SALT). That distinction matters: a plain
 * SHA-256 of an IPv4 address is reversible by anyone who has the code, because
 * there are only 4.3 billion addresses to try. Keyed, it is not reversible
 * without the secret — which is never stored beside the data it protects.
 *
 * If IP_SALT is ever unset the function still works, unkeyed, so a missing
 * secret degrades privacy rather than taking the service down.
 */
let DK_SALT = null, DK_KEY = null;
async function dkMacKey() {
  if (!DK_KEY) {
    DK_KEY = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(DK_SALT || "dk1-unsalted"),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  }
  return DK_KEY;
}
async function sha96(s) {
  const b = await crypto.subtle.sign("HMAC", await dkMacKey(), new TextEncoder().encode(s));
  return [...new Uint8Array(b)].slice(0, 12).map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function callerKey(request) {
  return "ip:" + (await sha96("dk1:" + (request.headers.get("CF-Connecting-IP") || "anon")));
}

/* --------------------------------------------------------------- paywall */
async function checkAccess(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const key = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  // ---- Pro: validate the licence key, then meter against the included allowance
  if (key) {
    let pro = false;
    if (env.RL) { try { if (await env.RL.get("pk:" + (await sha96("dk1:" + key)))) pro = true; } catch {} }
    if (!pro) {
      try {
        const v = await fetch("https://api.polar.sh/v1/customer-portal/license-keys/validate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key, organization_id: POLAR_ORG }),
        });
        if (v.ok) {
          const d = await v.json().catch(() => ({}));
          if (d && (!("status" in d) ? (d.valid || d.id) : d.status === "granted")) {
            pro = true;
            if (env.RL) { try { await env.RL.put("pk:" + (await sha96("dk1:" + key)), "1", { expirationTtl: 3600 }); } catch {} }
          }
        }
      } catch { /* upstream down: fall through to the invalid-key branch */ }
    }
    if (!pro) {
      // A supplied key that does not validate used to fall silently back to the
      // free tier, so a paying customer with a typo looked throttled for no reason.
      return { ok: false, pro: false, remaining: 0, limit: FREE_LIMIT, reason: "invalid_key" };
    }
    // Pro is metered but never blocked: overage is billed, not refused.
    if (env.QUOTA_DB) {
      try {
        const month = new Date().toISOString().slice(0, 7);
        const used = await bump(env, "pro:" + (await sha96("dk1:" + key)), month);
        return { ok: true, pro: true, used, included: PRO_INCLUDED, remaining: null, limit: null };
      } catch (e) { console.error("QUOTA error (pro):", e && e.message); }
    }
    return { ok: true, pro: true, remaining: null, limit: null };
  }

  // ---- Free: anonymous, keyless, 100 a day
  if (!env.QUOTA_DB) {
    // Fail OPEN so a misconfiguration never takes the API down — but say so.
    // The previous version failed open silently, which is how a completely
    // non-functional paywall stayed invisible for months.
    console.error("DATAKOOT METERING DISABLED: env.QUOTA_DB is not bound");
    return { ok: true, pro: false, remaining: null, limit: null, metered: false };
  }
  const day = new Date().toISOString().slice(0, 10);
  let n;
  try {
    n = await bump(env, await callerKey(request), day);
  } catch (e) {
    console.error("DATAKOOT METERING ERROR, failing open:", e && e.message);
    return { ok: true, pro: false, remaining: null, limit: null, metered: false };
  }
  // The Nth call writes n = N, so call FREE_LIMIT is the last allowed one and
  // call FREE_LIMIT + 1 is the first refused one.
  if (n > FREE_LIMIT) return { ok: false, pro: false, used: n, remaining: 0, limit: FREE_LIMIT, reason: "free_limit" };
  return { ok: true, pro: false, used: n, remaining: FREE_LIMIT - n, limit: FREE_LIMIT, metered: true };
}

/* Headers so a developer can watch the meter instead of guessing. */
function quotaHeaders(a) {
  if (!a || a.pro || a.limit == null) return {};
  const t = new Date();
  return {
    "X-RateLimit-Limit": String(a.limit),
    "X-RateLimit-Remaining": String(a.remaining == null ? a.limit : a.remaining),
    "X-RateLimit-Reset": String(Math.floor(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate() + 1) / 1000)),
  };
}

/* ------------------------------------------------------------- data layer */
async function npmMeta(name) {
  const d = await getJSON(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if (d._notfound || d._error) return d;
  const latest = d["dist-tags"] && d["dist-tags"].latest;
  const v = latest && d.versions ? d.versions[latest] : {};
  return {
    ecosystem: "npm", name: d.name, version: latest,
    description: d.description || (v && v.description) || null,
    license: (v && v.license) || d.license || null,
    homepage: d.homepage || null,
    repository: v && v.repository ? (v.repository.url || v.repository) : (d.repository && (d.repository.url || d.repository)) || null,
    maintainers: (d.maintainers || []).map((m) => m.name).slice(0, 10),
    published: d.time && latest ? d.time[latest] : null,
    last_publish: d.time && d.time.modified ? d.time.modified : null,
    deprecated: !!(v && v.deprecated),
    version_count: d.versions ? Object.keys(d.versions).length : null,
  };
}
async function pypiMeta(name) {
  const d = await getJSON(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (d._notfound || d._error) return d;
  const i = d.info || {};
  const urls = i.project_urls || {};
  return {
    ecosystem: "pypi", name: i.name, version: i.version,
    description: i.summary || null,
    license: i.license || (i.classifiers || []).find((c) => c.startsWith("License ::")) || null,
    homepage: i.home_page || urls.Homepage || urls.Home || null,
    repository: urls.Source || urls.Repository || urls["Source Code"] || null,
    maintainers: [i.author, i.maintainer].filter(Boolean).slice(0, 10),
    published: null,
    deprecated: false,
    requires_python: i.requires_python || null,
    version_count: d.releases ? Object.keys(d.releases).length : null,
  };
}
async function cratesMeta(name) {
  const d = await getJSON(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`);
  if (d._notfound || d._error || !d.crate) return d._notfound || d._error ? d : { _notfound: true };
  const c = d.crate;
  const newest = (d.versions || []).find((v) => v.num === c.max_stable_version) || (d.versions || [])[0] || {};
  return {
    ecosystem: "cargo", name: c.name, version: c.max_stable_version || c.max_version,
    description: c.description || null,
    license: newest.license || null,
    homepage: c.homepage || null,
    repository: c.repository || null,
    maintainers: [],
    published: c.updated_at || null,
    deprecated: false,
    version_count: (d.versions || []).length,
  };
}
async function metaFor(system, name) {
  if (system === "npm") return npmMeta(name);
  if (system === "pypi") return pypiMeta(name);
  if (system === "cargo") return cratesMeta(name);
  return { _error: "unknown ecosystem" };
}

async function downloadsFor(system, name) {
  if (system === "npm") {
    const d = await getJSON(`https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(name)}`);
    return d && !d._error ? { ecosystem: "npm", last_month: d.downloads ?? null } : d;
  }
  if (system === "pypi") {
    // PyPI's official API does not expose per-package download counts (they live in a
    // Google BigQuery public dataset). We deliberately avoid third-party stat mirrors to
    // keep every source cleanly licensable for resale.
    return { ecosystem: "pypi", downloads: null, note: "PyPI does not publish per-package download counts through its official API. Use package_health and package_info for maintenance and adoption signals instead." };
  }
  if (system === "cargo") {
    const d = await getJSON(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`);
    return d && d.crate ? { ecosystem: "cargo", total: d.crate.downloads, recent_90d: d.crate.recent_downloads } : { _notfound: true };
  }
  return { _error: "unknown ecosystem" };
}

// deps.dev: version data (licenses + advisories) for package_health.
async function depsDev(system, name, version) {
  const sys = { npm: "npm", pypi: "pypi", cargo: "cargo" }[system];
  if (!version) {
    const p = await getJSON(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(name)}`);
    if (p._error || p._notfound) return { version: null, pkg: p };
    const def = (p.versions || []).find((v) => v.isDefault) || (p.versions || [])[p.versions.length - 1];
    version = def && def.versionKey ? def.versionKey.version : null;
  }
  if (!version) return { version: null, _error: "no version" };
  const v = await getJSON(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`);
  // Pass the failure up rather than handing back an object whose missing fields
  // would later be read as "this package has no dependencies / no licence".
  if (v && (v._error || v._notfound)) return { version, data: v, _error: v._error || "not found" };
  return { version, data: v };
}

/* ------------------------------------------------------------------- tools */
const DK_AD = {"*.ecosystem":"Package registry to look in. One of: npm, pypi, cargo.","*.name":"Exact package name as published in that registry, e.g. express for npm, requests for pypi, serde for cargo.","*.limit":"Maximum number of results to return.","package_search.query":"Free-text search terms, matched against package names and descriptions."};
function dkDescribe(ts) { try { for (const t of ts) { const p = ((t.inputSchema || {}).properties) || {}; for (const k of Object.keys(p)) { const d = DK_AD[t.name + "." + k] || DK_AD["*." + k]; if (d && p[k] && !p[k].description) p[k].description = d; } } } catch (e) {} return ts; }
const TOOLS = [
  {
    name: "package_info",
    description: "Get core metadata for a package: latest version, description, license, homepage, source repository, maintainers, and whether it is deprecated. Use before an agent installs or recommends a dependency. Ecosystems: npm, pypi, cargo.",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string", enum: ["npm", "pypi", "cargo"] }, name: { type: "string", description: "Package/crate name" } }, required: ["ecosystem", "name"] },
  },
  {
    name: "package_versions",
    description: "List recent released versions of a package with release dates (most recent first). Helps an agent pick a version or check how actively it is maintained. Ecosystems: npm, pypi, cargo.",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string", enum: ["npm", "pypi", "cargo"] }, name: { type: "string" }, limit: { type: "integer", default: 15 } }, required: ["ecosystem", "name"] },
  },
  {
    name: "package_downloads",
    description: "Get popularity/download statistics for a package (recent download counts). Useful for judging how widely used and battle-tested a dependency is. Ecosystems: npm, pypi, cargo.",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string", enum: ["npm", "pypi", "cargo"] }, name: { type: "string" } }, required: ["ecosystem", "name"] },
  },
  {
    name: "package_dependencies",
    description: "List the direct dependencies of a specific package version (defaults to latest), via deps.dev. Lets an agent understand what a package pulls in before adding it. Ecosystems: npm, pypi, cargo.",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string", enum: ["npm", "pypi", "cargo"] }, name: { type: "string" }, version: { type: "string", description: "Optional; defaults to the latest/default version" } }, required: ["ecosystem", "name"] },
  },
  {
    name: "package_health",
    description: "A composite trust/health check for a package an agent is considering: latest-release recency, deprecation status, license present, maintainer count, dependency count, and any known security advisories (via deps.dev). Returns a summary an agent can act on. Ecosystems: npm, pypi, cargo.",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string", enum: ["npm", "pypi", "cargo"] }, name: { type: "string" } }, required: ["ecosystem", "name"] },
  },
  {
    name: "package_search",
    description: "Search for packages by keyword and get the top matches with descriptions. Supported ecosystems: npm and cargo (PyPI has no public search API).",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string", enum: ["npm", "cargo"] }, query: { type: "string" }, limit: { type: "integer", default: 10 } }, required: ["ecosystem", "query"] },
  },
];

async function runTool(name, args) {
  const system = normEco(args.ecosystem);
  if (["package_info", "package_versions", "package_downloads", "package_dependencies", "package_health"].includes(name) && !system)
    return { error: "Unsupported ecosystem. Use one of: npm, pypi, cargo." };

  if (name === "package_info") {
    const m = await metaFor(system, args.name);
    if (m._notfound) return { error: `Package '${args.name}' not found on ${system}.` };
    return m;
  }
  if (name === "package_versions") {
    const limit = Math.min(args.limit || 15, 50);
    if (system === "npm") {
      const d = await getJSON(`https://registry.npmjs.org/${encodeURIComponent(args.name)}`);
      if (d._notfound) return { error: "not found" };
      const times = d.time || {};
      const vers = Object.keys(d.versions || {}).map((v) => ({ version: v, released: times[v] || null }))
        .sort((a, b) => new Date(b.released || 0) - new Date(a.released || 0)).slice(0, limit);
      return { ecosystem: "npm", name: d.name, latest: d["dist-tags"] && d["dist-tags"].latest, versions: vers };
    }
    if (system === "pypi") {
      const d = await getJSON(`https://pypi.org/pypi/${encodeURIComponent(args.name)}/json`);
      if (d._notfound) return { error: "not found" };
      const rel = d.releases || {};
      const vers = Object.keys(rel).map((v) => ({ version: v, released: rel[v] && rel[v][0] ? rel[v][0].upload_time_iso_8601 : null, yanked: rel[v] && rel[v][0] ? rel[v][0].yanked : false }))
        .sort((a, b) => new Date(b.released || 0) - new Date(a.released || 0)).slice(0, limit);
      return { ecosystem: "pypi", name: d.info.name, latest: d.info.version, versions: vers };
    }
    if (system === "cargo") {
      const d = await getJSON(`https://crates.io/api/v1/crates/${encodeURIComponent(args.name)}`);
      if (!d.crate) return { error: "not found" };
      const vers = (d.versions || []).map((v) => ({ version: v.num, released: v.created_at, yanked: v.yanked })).slice(0, limit);
      return { ecosystem: "cargo", name: d.crate.name, latest: d.crate.max_stable_version, versions: vers };
    }
  }
  if (name === "package_downloads") return await downloadsFor(system, args.name);
  if (name === "package_dependencies") {
    const sys = { npm: "npm", pypi: "pypi", cargo: "cargo" }[system];
    let version = args.version;
    if (!version) {
      const p = await getJSON(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(args.name)}`);
      if (p._error || p._notfound) return { error: `Package '${args.name}' not found on ${system}.` };
      const def = (p.versions || []).find((v) => v.isDefault) || (p.versions || [])[p.versions.length - 1];
      version = def && def.versionKey ? def.versionKey.version : null;
    }
    if (!version) return { error: "could not determine a version to resolve dependencies for" };
    const d = await getJSON(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(args.name)}/versions/${encodeURIComponent(version)}:dependencies`);
    if (d._error || d._notfound || !d.nodes) return { error: "dependency data unavailable for that package/version" };
    const direct = d.nodes.filter((n) => n.relation === "DIRECT").map((n) => ({ name: n.versionKey && n.versionKey.name, version: n.versionKey && n.versionKey.version }));
    return { ecosystem: system, name: args.name, version, direct_dependency_count: direct.length, direct_dependencies: direct };
  }
  if (name === "package_health") {
    const m = await metaFor(system, args.name);
    if (m._notfound) return { error: `Package '${args.name}' not found on ${system}.` };
    const dd = await depsDev(system, args.name);
    const advisories = dd.data && dd.data.advisoryKeys ? dd.data.advisoryKeys.map((a) => a.id) : [];
    const last = m.published || m.last_publish;
    const ageDays = last ? Math.round((Date.now() - new Date(last)) / 86400000) : null;
    const signals = {
      latest_version: m.version,
      last_release: last,
      days_since_release: ageDays,
      actively_maintained: ageDays != null ? ageDays < 365 : null,
      deprecated: m.deprecated,
      has_license: !!m.license,
      license: m.license,
      maintainers: (m.maintainers || []).length || null,
      known_advisories: advisories.length,
      advisory_ids: advisories.slice(0, 10),
      repository: m.repository,
    };
    const concerns = [];
    if (m.deprecated) concerns.push("package is deprecated");
    if (advisories.length) concerns.push(`${advisories.length} known security advisory(ies)`);
    if (!m.license) concerns.push("no license metadata");
    if (ageDays != null && ageDays > 730) concerns.push("no release in 2+ years");
    signals.verdict = concerns.length === 0 ? "looks healthy" : "review before use";
    signals.concerns = concerns;
    return signals;
  }
  if (name === "package_search") {
    const limit = Math.min(args.limit || 10, 25);
    if (system === "npm" || args.ecosystem === "npm") {
      const d = await getJSON(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(args.query)}&size=${limit}`);
      // Without this, an upstream failure fell through to `results: []`, which
      // reads as "nothing matches your query" rather than "the search did not run".
      if (d._error) return { error: "The npm search API is not answering right now (" + d._error + "). This is an upstream failure, NOT a statement that nothing matches '" + args.query + "'. Try again shortly." };
      const objs = d.objects || [];
      return { ecosystem: "npm", query: args.query, result_count: objs.length, results: objs.map((o) => ({ name: o.package.name, version: o.package.version, description: o.package.description, links: o.package.links })) };
    }
    if (system === "cargo" || args.ecosystem === "cargo") {
      const d = await getJSON(`https://crates.io/api/v1/crates?q=${encodeURIComponent(args.query)}&per_page=${limit}`);
      if (d._error) return { error: "The crates.io search API is not answering right now (" + d._error + "). This is an upstream failure, NOT a statement that nothing matches '" + args.query + "'. Try again shortly." };
      const cr = d.crates || [];
      return { ecosystem: "cargo", query: args.query, result_count: cr.length, results: cr.map((c) => ({ name: c.name, version: c.max_stable_version, description: c.description, downloads: c.downloads })) };
    }
    return { error: "Search supports npm and cargo only." };
  }
  return { error: "unknown tool" };
}

/* --------------------------------------------------------------- MCP core */
function rpc(id, result) { return { jsonrpc: "2.0", id, result }; }
function rpcErr(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }

async function handleMCP(request, env) {
  let body;
  try { body = await request.json(); } catch { return json(rpcErr(null, -32700, "Parse error")); }
  const { id, method, params } = body || {};
  console.log("DKPULSE " + (method || "?") + " " + ((params && params.name) || "-"));

  if (method === "initialize") {
    return json(rpc(id, {
      protocolVersion: dkProto(params),
      capabilities: { tools: {} },
      serverInfo: SERVER,
      instructions: "Package Intel: live metadata, popularity, dependencies, and health/advisory signals for npm, PyPI, and crates.io packages. Call package_health before trusting an unfamiliar dependency.",
    }));
  }
  if (method === "notifications/initialized" || method === "notifications/cancelled") return new Response(null, { status: 202, headers: CORS });
  if (method === "ping") return json(rpc(id, {}));
  if (method === "tools/list") return json(rpc(id, { tools: dkDescribe(TOOLS) }));

  if (method === "tools/call") {
    const access = await checkAccess(request, env);
    if (!access.ok) {
      const msg = access.reason === "invalid_key"
        ? `That Datakoot API key was not recognised. Check it at https://datakoot.com/pricing, or remove the Authorization header to use the free tier (${FREE_LIMIT} calls/day, no signup).`
        : `Daily free limit reached (${access.limit} calls). It resets at 00:00 UTC. Datakoot Pro includes ${PRO_INCLUDED.toLocaleString()} calls a month across all nine servers for $15, then $5 per ${OVERAGE_PER.toLocaleString()} — ${CHECKOUT}`;
      return json(rpc(id, { content: [{ type: "text", text: msg }], isError: true }), 200, quotaHeaders(access));
    }
    const tname = params && params.name;
    const args = (params && params.arguments) || {};
    const tool = TOOLS.find((t) => t.name === tname);
    // The call was counted, so it reports the meter like any other response.
    if (!tool) return json(rpcErr(id, -32602, `Unknown tool: ${tname}`), 200, quotaHeaders(access)); { const _s = ((tool && tool.inputSchema) || {}).properties || {}; const _rq = ((tool || {}).inputSchema || {}).required || []; const _bad = Object.keys(args).filter((k) => !(k in _s)).map((k) => "unexpected '" + k + "'").concat(_rq.filter((k) => args[k] === undefined || args[k] === null || args[k] === "").map((k) => "missing required '" + k + "'")); if (_bad.length) return json(rpcErr(id, -32602, "Bad arguments for " + tname + ": " + _bad.join(", ") + ". Valid: " + (Object.keys(_s).join(", ") || "none") + ". The call was refused rather than ignoring them, because ignoring an argument returns a confident answer to a different question than the one asked."), 200, quotaHeaders(access)); }
    try {
      const out = await runTool(tname, args);
      const text = JSON.stringify(out, null, 2);
      const meta = access.pro
        ? (access.used > PRO_INCLUDED ? `\n\n(${access.used.toLocaleString()} calls this month — ${(access.used - PRO_INCLUDED).toLocaleString()} over the ${PRO_INCLUDED.toLocaleString()} included)` : "")
        : (access.remaining == null ? "" : `\n\n(${access.remaining} free calls left today)`);
      return json(rpc(id, { content: [{ type: "text", text: text + meta }], isError: !!(out && out.error) }), 200, quotaHeaders(access));
    } catch (e) {
      return json(rpc(id, { content: [{ type: "text", text: "Error: " + (e && e.message || String(e)) }], isError: true }), 200, quotaHeaders(access));
    }
  }
  return json(rpcErr(id, -32601, `Method not found: ${method}`));
}

/* ----------------------------------------------------------------- landing */
const CSS = `:root{--bg:#0b0e14;--panel:#111725;--border:#1e2636;--text:#e6edf3;--muted:#8b98a9;--accent:#4ade80;--accent2:#22d3ee}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;line-height:1.6}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px}
header{position:sticky;top:0;z-index:50;background:#0b0e14;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:18px;padding:12px 20px}
.logo{display:flex;align-items:center;gap:9px;font-weight:800;font-size:19px}
.logo svg{display:block}
nav{display:flex;gap:16px;margin-left:auto;flex-wrap:wrap;font-size:14px}
nav a{color:var(--muted)}nav a:hover{color:var(--text)}
.hero{padding:64px 0 32px}.hero h1{font-size:44px;line-height:1.1;margin:0 0 14px}.hero .accent{color:var(--accent)}
.sub{font-size:19px;color:var(--muted);max-width:620px}
.section{padding:28px 0;border-top:1px solid var(--border)}
.grid{display:grid;grid-template-columns:1fr;gap:16px}@media(min-width:760px){.grid{grid-template-columns:1fr 1fr}}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;min-width:0}
.card h3{margin:0 0 6px;font-size:16px}.card code{color:var(--accent);font-size:13px}.card p{margin:6px 0 0;color:var(--muted);font-size:14px}
.cmd{display:flex;align-items:center;gap:8px;background:#0a0d13;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:14px 0;overflow-x:auto}
.cmd code{font:13px/1.5 ui-monospace,Menlo,monospace;color:var(--text);white-space:nowrap}
.tiers{display:grid;grid-template-columns:1fr;gap:14px}@media(min-width:760px){.tiers{grid-template-columns:1fr 1fr 1fr}}
.tier{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px}.tier b{font-size:18px}.tier span{display:block;color:var(--muted);font-size:14px;margin-top:4px}
.btn{display:inline-block;background:var(--accent);color:#06210f;font-weight:700;padding:10px 18px;border-radius:8px;margin-top:8px}
footer{border-top:1px solid var(--border);padding:32px 20px;color:var(--muted);font-size:14px;text-align:center}`;

const MARK = `<svg width="26" height="26" viewBox="-34 -34 68 68" style="vertical-align:-4px"><g stroke="#4ade80" stroke-width="5" fill="none" stroke-linejoin="round"><polygon points="0,-30 26,-15 26,15 0,30 -26,15 -26,-15"/></g><g fill="#4ade80"><circle cx="0" cy="-12" r="6"/><circle cx="-11" cy="8" r="6"/><circle cx="11" cy="8" r="6"/></g></svg>`;

function landing(host) {
  const ep = `https://${host}/mcp`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Package Intel MCP — Vet any dependency before your agent installs it | Datakoot</title>
<meta name="description" content="Keyless MCP server giving AI agents live package intelligence across npm, PyPI and crates.io: metadata, versions, popularity, dependencies, known advisories and a health score.">
<style>${CSS}</style></head><body>
<header><a href="https://datakoot.com/" style="color:inherit"><div class="logo">${MARK}Data<span style="color:var(--accent)">koot</span></div></a>
<nav><a href="https://datakoot.com/">Datakoot</a><a href="#tools">Tools</a><a href="#start">Quick start</a><a href="#pricing">Pricing</a><a href="https://github.com/datakoot">GitHub</a></nav></header>
<div class="wrap">
<section class="hero"><h1>Know what your agent is about to <span class="accent">install</span>.</h1>
<p class="sub">Package Intel gives AI agents live metadata, popularity, dependencies, and security-advisory signals across npm, PyPI, and crates.io — so they choose dependencies with eyes open. No API keys.</p></section>

<section class="section" id="tools"><h2>Tools</h2><div class="grid">
<div class="card"><h3><code>package_info</code></h3><p>Latest version, license, repo, maintainers, deprecation.</p></div>
<div class="card"><h3><code>package_versions</code></h3><p>Recent versions with release dates.</p></div>
<div class="card"><h3><code>package_downloads</code></h3><p>Popularity / download counts.</p></div>
<div class="card"><h3><code>package_dependencies</code></h3><p>Direct dependencies of a version (deps.dev).</p></div>
<div class="card"><h3><code>package_health</code></h3><p>Composite trust check: freshness, deprecation, license, maintainers, known advisories.</p></div>
<div class="card"><h3><code>package_search</code></h3><p>Find packages by keyword (npm, crates.io).</p></div>
</div></section>

<section class="section" id="start"><h2>Quick start</h2>
<p class="sub">One line, no key. Works with Claude, Cursor, and any MCP client.</p>
<div class="cmd"><code>claude mcp add --transport http package-intel ${ep}</code></div>
<p style="color:var(--muted);font-size:14px">Or point any MCP client at <code>${ep}</code></p></section>

<section class="section" id="pricing"><h2>Pricing</h2><div class="tiers">
<div class="tier"><b>Free</b><span>100 calls / day</span><span>Every tool, no key, no signup.</span></div>
<div class="tier"><b>$15/mo · Pro</b><span>10,000 calls / month</span><span>1 seat · one key unlocks all nine Datakoot servers · then $5 per 1,000, capped at $100.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
<div class="tier"><b>$49/mo · Team</b><span>50,000 calls / month</span><span>Up to 5 seats · then $5 per 1,000.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
</div></section>
</div>
<footer><a href="https://datakoot.com/" style="color:inherit">Datakoot</a> — infrastructure for the agent economy · <a href="https://github.com/datakoot">GitHub</a> · Data: npm, PyPI, crates.io, deps.dev</footer>
</body></html>`;
}

/* ------------------------------------------------------------------ router */
export default {
  async fetch(request, env) {
    if (DK_SALT === null) DK_SALT = env.IP_SALT || "";
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(request.url);
    if (url.pathname.endsWith("/.well-known/owners.json")) return json({ $schema: "https://verifymcp.io/schemas/owners.json", owners: ["hello@datakoot.com"] });
    if (url.pathname === "/mcp" || url.pathname === "/sse") {
      if (request.method === "POST") return handleMCP(request, env);
      return json({ error: "POST JSON-RPC to this endpoint (MCP streamable HTTP)" }, 405);
    }
    if (url.pathname === "/health") return json({ ok: true, server: SERVER });
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(landing(url.host), { headers: { "Content-Type": "text/html; charset=utf-8", ...CORS } });
    }
    return new Response("Not found", { status: 404, headers: CORS });
  },
};

/* MCP protocol negotiation.
 *
 * Echo back the version the client asked for when we speak it, otherwise answer
 * with the newest one we do. These servers answered a hardcoded "2024-11-05" to
 * every client, which meant no client could rely on structuredContent or
 * outputSchema — both introduced in 2025-06-18. Same list and same behaviour as
 * base-intel and domain-intel, which already did this correctly.
 */
const DK_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
function dkProto(params) {
  const want = params && params.protocolVersion;
  return DK_PROTOCOL_VERSIONS.indexOf(want) !== -1 ? want : DK_PROTOCOL_VERSIONS[0];
}

/* Retention analytics.
 *
 * `quota` keeps ONE row per caller and overwrites it when the day rolls over,
 * so it can only ever show a caller's most recent active day. That makes the
 * most valuable question — did anyone come back tomorrow? — structurally
 * unanswerable. `daily` keeps one row per caller PER DAY instead.
 *
 * It stores exactly what `quota` stores: the same keyed, non-reversible caller
 * identifier, a date, a count. No queries, no addresses, nothing new about
 * anyone. The 04:17 retention job prunes it on the same 90-day clock, so the
 * privacy policy stays true.
 *
 * Wrapped so it can never break a caller's request: if this write fails the
 * call still succeeds and metering is unaffected. It is analytics, not billing.
 */
const DK_DAILY_SQL =
  "INSERT INTO daily (k, period, n, updated) VALUES (?1, ?2, 1, ?3) " +
  "ON CONFLICT(k, period) DO UPDATE SET n = daily.n + 1, updated = excluded.updated";
async function dkDaily(env, k, period) {
  try {
    await env.QUOTA_DB.prepare(DK_DAILY_SQL)
      .bind(k, period, Math.floor(Date.now() / 1000)).run();
  } catch (e) { /* never let analytics break a paying or free call */ }
}