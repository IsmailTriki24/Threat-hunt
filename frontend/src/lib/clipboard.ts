/** Copy text to the clipboard and report whether it worked.
 *  `navigator.clipboard` only exists in secure contexts (HTTPS or localhost); the platform is often opened over plain HTTP on a LAN address, where the
 *  call is simply undefined. Fall back to a transient textarea + `document.execCommand("copy")`, which works in that case. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* permission denied or blocked: try the fallback */ }
  if (typeof document === "undefined") return false;
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.setAttribute("aria-hidden", "true");
  ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;pointer-events:none";
  const prev = document.activeElement as HTMLElement | null;
  document.body.appendChild(ta);
  try {
    ta.focus({ preventScroll: true }); // some browsers only copy a focused, selected element
    ta.select();
    ta.setSelectionRange(0, text.length);
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    ta.remove();
    prev?.focus?.();
  }
}
