export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/players") {
      try {
        if (!env.DB) {
          return Response.json(
            { error: "DB binding is missing" },
            { status: 500 }
          );
        }

        const result = await env.DB.prepare(
          "SELECT * FROM players ORDER BY id"
        ).all();

        return Response.json(result.results);

      } catch (error) {
        return Response.json(
          {
            error: String(error),
            message: error?.message || "Unknown error"
          },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
