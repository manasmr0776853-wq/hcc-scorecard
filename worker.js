const COOKIE_NAME = "hcc_admin";

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);

  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  return toBase64Url(new Uint8Array(signature));
}

async function isAdmin(request, secret) {
  if (!secret) return false;

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)hcc_admin=([^;]+)/);

  if (!match) return false;

  try {
    const parts = match[1].split(".");
    if (parts.length !== 2) return false;

    const [payload, signature] = parts;
    const expected = await sign(payload, secret);

    if (signature !== expected) return false;

    const data = JSON.parse(
      new TextDecoder().decode(fromBase64Url(payload))
    );

    return data.exp > Date.now();
  } catch {
    return false;
  }
}

const STAT_FIELDS = {
  matches: "INTEGER",
  innings: "INTEGER",
  runs: "INTEGER",
  balls_faced: "INTEGER",
  highest_score: "INTEGER",
  batting_average: "REAL",
  strike_rate: "REAL",
  wickets: "INTEGER",
  balls_bowled: "INTEGER",
  runs_conceded: "INTEGER",
  economy: "REAL",
  bowling_average: "REAL"
};

const TEXT_FIELDS = {
  best_batting: true,
  best_bowling: true
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ADMIN LOGIN
    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        if (
          !env.ADMIN_PASSWORD ||
          typeof body.password !== "string" ||
          body.password !== env.ADMIN_PASSWORD
        ) {
          return Response.json(
            { success: false, message: "Incorrect password" },
            { status: 401 }
          );
        }

        const payload = toBase64Url(
          new TextEncoder().encode(
            JSON.stringify({
              exp: Date.now() + 60 * 60 * 1000
            })
          )
        );

        const signature = await sign(
          payload,
          env.ADMIN_PASSWORD
        );

        const token = `${payload}.${signature}`;

        return Response.json(
          { success: true },
          {
            headers: {
              "Set-Cookie":
                `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`,
              "Cache-Control": "no-store"
            }
          }
        );
      } catch {
        return Response.json(
          { success: false, message: "Invalid request" },
          { status: 400 }
        );
      }
    }

    // ADMIN LOGOUT
    if (
      url.pathname === "/api/logout" &&
      request.method === "POST"
    ) {
      return Response.json(
        { success: true },
        {
          headers: {
            "Set-Cookie":
              `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`,
            "Cache-Control": "no-store"
          }
        }
      );
    }

    // LOAD ALL PLAYERS
    if (
      url.pathname === "/api/players" &&
      request.method === "GET"
    ) {
      try {
        const result = await env.DB.prepare(
          "SELECT * FROM players ORDER BY id"
        ).all();

        return Response.json(result.results, {
          headers: { "Cache-Control": "no-store" }
        });
      } catch {
        return Response.json(
          { error: "Could not load players" },
          { status: 500 }
        );
      }
    }

    // UPDATE PLAYER STATISTICS
    if (
      url.pathname === "/api/players" &&
      request.method === "POST"
    ) {
      if (!(await isAdmin(request, env.ADMIN_PASSWORD))) {
        return Response.json(
          { error: "Admin login required" },
          { status: 401 }
        );
      }

      try {
        const body = await request.json();
        const id = Number(body.id);

        if (!Number.isInteger(id) || id < 1) {
          return Response.json(
            { error: "Invalid player ID" },
            { status: 400 }
          );
        }

        const updates = [];

        for (const [field, type] of Object.entries(STAT_FIELDS)) {
          if (body[field] === undefined) continue;

          const value = body[field];

          if (
            typeof value !== "number" ||
            !Number.isFinite(value) ||
            value < 0 ||
            (type === "INTEGER" && !Number.isInteger(value))
          ) {
            return Response.json(
              { error: `Invalid value for ${field}` },
              { status: 400 }
            );
          }

          updates.push({ field, value });
        }

        for (const field of Object.keys(TEXT_FIELDS)) {
          if (body[field] === undefined) continue;

          if (
            typeof body[field] !== "string" ||
            body[field].length > 50
          ) {
            return Response.json(
              { error: `Invalid value for ${field}` },
              { status: 400 }
            );
          }

          updates.push({
            field,
            value: body[field]
          });
        }

        if (updates.length === 0) {
          return Response.json(
            { error: "No statistics provided" },
            { status: 400 }
          );
        }

        const assignments = updates
          .map(item => `${item.field} = ?`)
          .join(", ");

        const values = updates.map(item => item.value);

        const result = await env.DB.prepare(
          `UPDATE players SET ${assignments} WHERE id = ?`
        )
          .bind(...values, id)
          .run();

        if (result.meta.changes === 0) {
          const player = await env.DB.prepare(
            "SELECT id FROM players WHERE id = ?"
          )
            .bind(id)
            .first();

          if (!player) {
            return Response.json(
              { error: "Player not found" },
              { status: 404 }
            );
          }
        }

        return Response.json({ success: true });
      } catch {
        return Response.json(
          { error: "Could not update player statistics" },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
