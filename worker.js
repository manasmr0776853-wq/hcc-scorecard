export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Get all players
    if (url.pathname === "/api/players" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT * FROM players ORDER BY id"
      ).all();

      return Response.json(result.results);
    }

    // Update a player's statistics
    if (url.pathname === "/api/players" && request.method === "POST") {
      return Response.json({
        message: "Admin update system is ready"
      });
    }

    return env.ASSETS.fetch(request);
  }
};
