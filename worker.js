export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    };

    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();

        if (
          !env.ADMIN_PASSWORD ||
          typeof body.password !== "string" ||
          body.password !== env.ADMIN_PASSWORD
        ) {
          return Response.json(
            { success: false, message: "Incorrect password" },
            { status: 401, headers: cors }
          );
        }

        return Response.json(
          { success: true },
          { headers: cors }
        );
      } catch {
        return Response.json(
          { success: false, message: "Invalid request" },
          { status: 400, headers: cors }
        );
      }
    }

    if (url.pathname === "/api/players" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT * FROM players ORDER BY id"
      ).all();

      return Response.json(result.results, { headers: cors });
    }

    if (url.pathname === "/api/players" && request.method === "POST") {
      return Response.json(
        { error: "Protected player updates are not implemented yet." },
        { status: 501, headers: cors }
      );
    }

    return env.ASSETS.fetch(request);
  }
};
