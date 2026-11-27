
async function verifyAdmin(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.match(/(?:^|;\s*)admin_session=([^;]+)/)?.[1];

  if (!token || !env.SESSION_SECRET || !env.DB) return null;

  try {
    const [payloadPart, signaturePart] = token.split(".");
    if (!payloadPart || !signaturePart) return null;

    const decode = value => {
      const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
      return Uint8Array.from(
        atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")),
        c => c.charCodeAt(0)
      );
    };

    const payload = JSON.parse(
      new TextDecoder().decode(decode(payloadPart))
    );

    if (!payload.email || payload.expires <= Math.floor(Date.now() / 1000)) {
      return null;
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
      decode(signaturePart),
      new TextEncoder().encode(payloadPart)
    );

    if (!valid) return null;

    const admin = await env.DB.prepare(
      "SELECT email FROM admins WHERE email = ? AND is_active = 1"
    ).bind(payload.email).first();

    return admin ? payload.email : null;
  } catch {
    return null;
  }
}

export async function onRequestGet({ request, env }) {
  const email = await verifyAdmin(request, env);

  if (!email) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const result = await env.DB.prepare(
    "SELECT email, login_time, ip_address FROM login_logs ORDER BY id DESC LIMIT 100"
  ).all();

  return Response.json({
    logs: result.results || []
  }, {
    headers: {
      "Cache-Control": "no-store"
    }
  });
}
