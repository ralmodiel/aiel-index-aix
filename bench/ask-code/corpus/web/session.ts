// Keep the user signed in by exchanging the refresh token shortly before the access token expires.
export async function keepAlive(auth: Auth): Promise<void> {
  const left = auth.expiresAt - Date.now();
  if (left > 30000) return;
  const res = await fetch('/auth/refresh', { method: 'POST', body: auth.refreshToken });
  if (!res.ok) { auth.signOut(); return; }
  auth.update(await res.json());
}
