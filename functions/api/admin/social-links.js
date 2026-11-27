
async function verifyAdmin(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.match(/(?:^|;\s*)admin_session=([^;]+)/)?.[1];

  if (!token || !env.SESSION_SECRET) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  try {
    const decode = value => {
      const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
      return Uint8Array.from(
        atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")),
        c => c.charCodeAt(0)
      );
    };

    const payload = JSON.parse(
      new TextDecoder().decode(decode(parts[0]))
    );

    if (!payload.email || payload.expires <= Math.floor(Date.now() / 1000)) {
      return false;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decode(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return false;

    const admin = await env.DB.prepare(
      "SELECT email FROM admins WHERE email = ? AND is_active = 1"
    ).bind(payload.email).first();

    return !!admin;
  } catch {
    return false;
  }
}

export async function onRequest({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  };

  if (request.method === "GET") {
    const result = await env.DB.prepare(
      "SELECT id, platform, url FROM social_links WHERE is_active = 1 ORDER BY id"
    ).all();

    return Response.json(result.results || [], { headers });
  }

  if (!["POST", "PUT", "DELETE"].includes(request.method)) {
    return Response.json({ error: "Method not allowed" }, {
      status: 405,
      headers
    });
  }

  if (!(await verifyAdmin(request, env))) {
    return Response.json({ error: "Unauthorized" }, {
      status: 401,
      headers
    });
  }

  try {
    if (request.method === "POST") {
      const { platform, url } = await request.json();

      if (
        typeof platform !== "string" ||
        typeof url !== "string" ||
        !platform.trim() ||
        !url.trim()
      ) {
        return Response.json({ error: "Platform and URL are required" }, {
          status: 400,
          headers
        });
      }

      const parsed = new URL(url);
      if (!["https:", "http:"].includes(parsed.protocol)) {
        return Response.json({ error: "Invalid URL" }, {
          status: 400,
          headers
        });
      }

      const result = await env.DB.prepare(
        "INSERT INTO social_links (platform, url) VALUES (?, ?)"
      ).bind(platform.trim(), parsed.toString()).run();

      return Response.json({
        success: true,
        id: result.meta.last_row_id
      }, { status: 201, headers });
    }

    const { id } = await request.json();

    if (!Number.isInteger(Number(id)) || Number(id) <= 0) {
      return Response.json({ error: "Valid link ID is required" }, {
        status: 400,
        headers
      });
    }

    if (request.method === "DELETE") {
      await env.DB.prepare(
        "UPDATE social_links SET is_active = 0 WHERE id = ?"
      ).bind(Number(id)).run();

      return Response.json({ success: true }, { headers });
    }

    const { platform, url } = await request.json();

    if (
      typeof platform !== "string" ||
      typeof url !== "string" ||
      !platform.trim() ||
      !url.trim()
    ) {
      return Response.json({ error: "Platform and URL are required" }, {
        status: 400,
        headers
      });
    }

    const parsed = new URL(url);
    if (!["https:", "http:"].includes(parsed.protocol)) {
      return Response.json({ error: "Invalid URL" }, {
        status: 400,
        headers
      });
    }

    await env.DB.prepare(
      "UPDATE social_links SET platform = ?, url = ? WHERE id = ?"
    ).bind(platform.trim(), parsed.toString(), Number(id)).run();

    return Response.json({ success: true }, { headers });

  } catch {
    return Response.json({ error: "Invalid request" }, {
      status: 400,
      headers
    });
  }
}
