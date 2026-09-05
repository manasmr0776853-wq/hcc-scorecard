export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/players") {
      const result = await env.DB.prepare(
        "SELECT * FROM players ORDER BY id"
      ).all();

      return Response.json(result.results);
    }

    return env.ASSETS.fetch(request);
  }
};
