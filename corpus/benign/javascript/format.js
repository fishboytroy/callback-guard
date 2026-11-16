// Pure formatting helpers. No network, no child processes.
export function slug(text) {
  return text.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-");
}

export function truncate(text, max) {
  return text.length <= max ? text : text.slice(0, max - 1) + "\u2026";
}
