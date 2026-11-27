
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const cookie = request.headers.get("Cookie") || "";
  const savedState = cookie.match(/(?:^|;\s*)oauth_state=([^;]+)/)?.[1];

  const headers = new Headers({
    "Set-Cookie": "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  });

  if (!code || !state || !savedState || state !== savedState) {
    return new Response("Invalid OAuth state. Please try again.", {
      status: 400,
      headers
    });
  }

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.DB || !env.SESSION_SECRET) {
    return new Response("Server configuration is incomplete.", {
      status: 500,
      headers
    });
  }

  const redirectUri = `${url.origin}/api/auth/callback`;

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code"
    })
  });

  const tokens = await tokenResponse.json();

  if (!tokenResponse.ok || !tokens.id_token) {
    return new Response("Google authentication failed.", {
      status: 401,
      headers
    });
  }

  const verifyResponse = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokens.id_token)}`
  );

  const user = await verifyResponse.json();
  const now = Math.floor(Date.now() / 1000);

  if (
    !verifyResponse.ok ||
    user.aud !== env.GOOGLE_CLIENT_ID ||
    user.iss !== "https://accounts.google.com" ||
    Number(user.exp) <= now ||
    user.email_verified !== "true" ||
    !user.email
  ) {
    return new Response("Google account verification failed.", {
      status: 401,
      headers
    });
  }

  const email = user.email.toLowerCase();

  const admin = await env.DB.prepare(
    "SELECT email FROM admins WHERE email = ? AND is_active = 1"
  ).bind(email).first();

  if (!admin) {
    return new Response("Access denied. This Gmail account is not authorized.", {
      status: 403,
      headers
    });
  }

  await env.DB.prepare(
    "INSERT INTO login_logs (email, ip_address) VALUES (?, ?)"
  ).bind(
    email,
    request.headers.get("CF-Connecting-IP") || null
  ).run();

  const sessionData = {
    email,
    expires: now + 86400
  };

  const payload = btoa(JSON.stringify(sessionData))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );

  const signatureText = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  headers.append(
    "Set-Cookie",
    `admin_session=${payload}.${signatureText}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
  );

  headers.set("Location", "/admin.html");

  return new Response(null, {
    status: 302,
    headers
  });
}
