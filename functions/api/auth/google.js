
export async function onRequestGet(context) {
  const { request, env } = context;

  if (!env.GOOGLE_CLIENT_ID) {
    return new Response("Google Client ID is not configured.", {
      status: 500
    });
  }

  const url = new URL(request.url);
  const redirectUri = `${url.origin}/api/auth/callback`;

  const stateBytes = new Uint8Array(32);
  crypto.getRandomValues(stateBytes);

  const state = Array.from(stateBytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  const googleUrl = new URL(
    "https://accounts.google.com/o/oauth2/v2/auth"
  );

  googleUrl.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
  googleUrl.searchParams.set("redirect_uri", redirectUri);
  googleUrl.searchParams.set("response_type", "code");
  googleUrl.searchParams.set("scope", "openid email profile");
  googleUrl.searchParams.set("state", state);

  const headers = new Headers();

  headers.set(
    "Set-Cookie",
    `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
  );

  headers.set("Location", googleUrl.toString());

  return new Response(null, {
    status: 302,
    headers
  });
}
