/** Restrict return destinations to Visor OT's asset routes. */
export function isSafeReturnPath(value) {
  return typeof value === "string" && /^\/assets(?:\/|\?|$)/.test(value)
    && !value.startsWith("//") && !/[\\\r\n]/.test(value);
}
export function sanitizeReturnState(state, depth = 0) {
  if (!state || typeof state !== "object" || depth >= 5 || !isSafeReturnPath(state.returnTo)) return null;
  return { returnTo: state.returnTo, returnState: sanitizeReturnState(state.returnState, depth + 1) };
}
export function navigationFromLocation(location) {
  return { returnTo: location.pathname + (location.search || "") + (location.hash || ""),
    returnState: sanitizeReturnState(location.state) };
}
export function getBackNavigation(location, fallback = "/assets") {
  const context = sanitizeReturnState(location.state);
  return { to: context?.returnTo || fallback, state: context?.returnState || null };
}
export function detailStateAfterEdit(location, id) {
  const back = getBackNavigation(location, "/assets/" + id);
  return back.to.split(/[?#]/)[0] === "/assets/" + id
    ? back.state || { returnTo: "/assets" }
    : { returnTo: back.to, returnState: back.state };
}
