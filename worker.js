export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const cors = {
      "Access-Control-Allow-Origin": url.origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    // Public: view all players
    if (url.pathname === "/api/players" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT * FROM players ORDER BY id"
      ).all();

      return Response.json(result.results, { headers: cors });
    }

    // Admin login
    if (url.pathname === "/api/login" && request.method === "POST") {
      const body = await request.json();

      if (
        !env.ADMIN_PASSWORD ||
        typeof body.password !== "string" ||
        body.password !== env.ADMIN_PASSWORD
      ) {
        return Response.json(
          { error: "Incorrect password" },
          { status: 401, headers: cors }
        );
      }

      const token = crypto.randomUUID() + crypto.randomUUID();

      await env.DB.prepare(
        "CREATE TABLE IF NOT EXISTS admin_sessions (token TEXT PRIMARY KEY, expires INTEGER NOT NULL)"
      ).run();

      await env.DB.prepare(
        "INSERT INTO admin_sessions (token, expires) VALUES (?, ?)"
      ).bind(token, Date.now() + 3600000).run();

      return Response.json(
        { token, message: "Login successful" },
        { headers: {
          ...cors,
          "Set-Cookie": `hcc_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`
        }}
      );
    }

    // Update player statistics: admin session required
    if (url.pathname === "/api/players" && request.method === "POST") {
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/(?:^|;\s*)hcc_admin=([a-f0-9-]+)/i);

      if (!match) {
        return Response.json(
          { error: "Please log in as admin" },
          { status: 401, headers: cors }
        );
      }

      const session = await env.DB.prepare(
        "SELECT token FROM admin_sessions WHERE token = ? AND expires > ?"
      ).bind(match[1], Date.now()).first();

      if (!session) {
        return Response.json(
          { error: "Session expired. Please log in again." },
          { status: 401, headers: cors }
        );
      }

      const body = await request.json();
      const allowed = [
        "matches", "innings", "runs", "balls",
        "highest_score", "batting_average", "strike_rate",
        "wickets", "balls_bowled", "runs_conceded",
        "economy", "bowling_average", "best"
      ];

      if (!Number.isInteger(Number(body.id)) || !body.stats ||
          typeof body.stats !== "object") {
        return Response.json(
          { error: "Invalid player data" },
          { status: 400, headers: cors }
        );
      }

      const fields = Object.keys(body.stats);

      if (!fields.length || fields.some(
        key => !allowed.includes(key) ||
          !Number.isFinite(Number(body.stats[key]))
      )) {
        return Response.json(
          { error: "Invalid statistics" },
          { status: 400, headers: cors }
        );
      }

      const assignments = fields.map(key => `${key} = ?`).join(", ");
      const values = fields.map(key => Number(body.stats[key]));

      const result = await env.DB.prepare(
        `UPDATE players SET ${assignments} WHERE id = ?`
      ).bind(...values, Number(body.id)).run();

      return Response.json(
        { success: true, updated: result.meta.changes },
        { headers: cors }
      );
    }

    return env.ASSETS.fetch(request);
  }
};
