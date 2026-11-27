
export async function onRequestPost() {
  return new Response(
    JSON.stringify({ success: true }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Set-Cookie": "admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
      }
    }
  );
}
