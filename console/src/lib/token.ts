import { useCallback, useEffect, useState } from "react";

/** The admin bearer token, kept in localStorage for this dev console only -- never
 * hardcode it (docs/14: "there is no default token"). The user pastes their own
 * ARGUS_ADMIN_TOKEN from .env. This is a demo convenience, not a production auth flow.
 */
const KEY = "argus_admin_token";

export function useAdminToken() {
  const [token, setTokenState] = useState<string>(() => localStorage.getItem(KEY) ?? "");

  useEffect(() => {
    const onStorage = () => setTokenState(localStorage.getItem(KEY) ?? "");
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const setToken = useCallback((t: string) => {
    localStorage.setItem(KEY, t);
    setTokenState(t);
  }, []);

  return { token, setToken };
}
