"use client";
import { useEffect, useRef } from "react";

/** idle: a calm hunt every few seconds · busy: signing in, the hunt quickens · denied: sign-in refused, the field stalls for a moment. */
export type SceneMode = "idle" | "busy" | "denied";

// The horizon sits at this fraction of the height (higher up on a phone, where the sign-in card takes the lower part);
// `.login-stage` in globals.css paints its glow at the same line.
const horizonFor = (w: number) => (w < 640 ? 0.2 : 0.36);
const NEAR = 1.7;
const FAR = 17;
const DOT = "201,195,250"; // lilac mist
const BRAND = "117,104,233"; // the product's periwinkle
const SIGNAL = "255,181,71"; // amber: used for the hunt and nothing else
const CORE = "255,240,214";

interface Host { x: number; z: number; r: number; tw: number; hot: boolean }
interface Hunt { chain: Host[]; t0: number; draw: number; hold: number; fade: number }

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));
const ease = (t: number) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

/**
 * A field of hosts seen in perspective, drifting toward the viewer. Now and then one amber trace follows a chain of hosts toward its target:
 * a lateral movement being hunted. Decorative only (aria-hidden); one canvas, no dependencies, still frame under reduced motion.
 */
export function LoginScene({ mode }: { mode: SceneMode }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const modeRef = useRef<SceneMode>(mode);
  useEffect(() => { modeRef.current = mode; }, [mode]);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return; // no canvas support (or a test DOM): the gradient behind it carries the page
    const still = !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    let w = 0, h = 0, f = 1, hz = 0.36;
    let avoid: { l: number; t: number; r: number; b: number } | null = null;
    let hosts: Host[] = [];
    let hunt: Hunt | null = null;
    let nextHunt = 0;
    let camX = 0, camTarget = 0, pointerX = 0, speed = 0.35;
    let raf = 0, last = 0;

    const spawn = (z: number): Host => ({
      x: (Math.random() - 0.5) * z * (w / f) * 1.3, z, r: 0.55 + Math.random() * 0.8, tw: 0.6 + Math.random() * 1.6, hot: Math.random() < 0.16,
    });
    const place = (p: Host) => ({ x: w / 2 + (p.x - camX) * (f / p.z), y: h * hz + f / p.z });

    const resize = () => {
      const box = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = Math.max(1, box.width); h = Math.max(1, box.height); f = h; hz = horizonFor(w);
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // weighted toward the horizon, where distance packs the hosts into a dense band
      hosts = Array.from({ length: clamp(Math.round((w * h) / 3400), 180, 520) }, () => spawn(NEAR + (FAR - NEAR) * Math.pow(Math.random(), 0.62)));
      hunt = null;
    };

    /** Keep the trace out from under the sign-in card (marked `data-scene-avoid`), so the one thing that moves is the thing you can see. */
    const measureAvoid = () => {
      const card = document.querySelector("[data-scene-avoid]")?.getBoundingClientRect();
      const me = canvas.getBoundingClientRect();
      avoid = card ? { l: card.left - me.left - 28, t: card.top - me.top - 28, r: card.right - me.left + 28, b: card.bottom - me.top + 28 } : null;
    };
    const hidden = (x: number, y: number) => !!avoid && x > avoid.l && x < avoid.r && y > avoid.t && y < avoid.b;
    const visible = (p: Host) => { const q = place(p); return q.x > w * 0.04 && q.x < w * 0.96 && q.y > h * 0.1 && q.y < h * 0.94 && !hidden(q.x, q.y); };

    /** A chain that walks toward the viewer, each hop to a close neighbour a little nearer than the last. */
    const plan = (now: number, quick: boolean): Hunt | null => {
      measureAvoid();
      const start = hosts.filter((p) => p.z > 6 && p.z < 13 && visible(p));
      if (!start.length) return null;
      const chain = [start[Math.floor(Math.random() * start.length)]];
      const reach = Math.min(w, h) * 0.3;
      while (chain.length < 6) {
        const from = place(chain[chain.length - 1]);
        const options = hosts
          .filter((p) => !chain.includes(p) && p.z < chain[chain.length - 1].z - 0.5 && p.z > NEAR + 1.2 && visible(p))
          .map((p) => ({ p, d: Math.hypot(place(p).x - from.x, place(p).y - from.y), q: place(p) }))
          .filter((o) => o.d < reach && o.d > reach * 0.15 && !hidden((o.q.x + from.x) / 2, (o.q.y + from.y) / 2))
          .sort((a, b) => a.d - b.d)
          .slice(0, 3);
        if (!options.length) break;
        chain.push(options[Math.floor(Math.random() * options.length)].p);
      }
      return chain.length >= 4 ? { chain, t0: now, draw: quick ? 1.5 : 2.8, hold: 1.5, fade: 1.2 } : null;
    };

    const drawHosts = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      const seen: { x: number; y: number; a: number; hot: boolean }[] = [];
      for (const p of hosts) {
        const { x, y } = place(p);
        if (x < -20 || x > w + 20 || y > h + 20) continue;
        const depth = clamp((FAR - p.z) / 4, 0, 1) * clamp((p.z - NEAR) / 1.0, 0, 1);
        const a = depth * (0.3 + 0.62 * (1 - p.z / FAR)) * (0.82 + 0.18 * Math.sin(t * p.tw + p.x));
        const r = p.r * (1.2 + 5.5 / p.z);
        if (p.hot) { ctx.fillStyle = `rgba(${BRAND},${a * 0.2})`; ctx.beginPath(); ctx.arc(x, y, r * 3.4, 0, 6.2832); ctx.fill(); seen.push({ x, y, a, hot: true }); }
        else seen.push({ x, y, a, hot: false });
        ctx.fillStyle = `rgba(${p.hot ? BRAND : DOT},${Math.min(1, a * (p.hot ? 1.6 : 1))})`;
        ctx.beginPath(); ctx.arc(x, y, r, 0, 6.2832); ctx.fill();
      }
      // the network: each brighter host reaches for its two nearest neighbours, so the field reads as machines talking, not stars
      const reach = Math.min(w, h) * 0.17;
      ctx.lineWidth = 1;
      for (const a of seen) {
        if (!a.hot) continue;
        const near = seen.filter((b) => b !== a).map((b) => ({ b, d: Math.hypot(a.x - b.x, a.y - b.y) })).filter((o) => o.d < reach).sort((m, n) => m.d - n.d).slice(0, 2);
        for (const { b, d } of near) {
          ctx.strokeStyle = `rgba(${DOT},${Math.min(a.a, b.a) * 0.3 * (1 - d / reach)})`;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    };

    const drawHunt = (hu: Hunt, t: number) => {
      const el = t - hu.t0;
      const head = el < hu.draw ? ease(el / hu.draw) : 1;
      const alpha = el < hu.draw + hu.hold ? 1 : 1 - (el - hu.draw - hu.hold) / hu.fade;
      const pts = hu.chain.map(place);
      const cum = [0];
      for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y));
      const total = cum[cum.length - 1];
      const reached = head * total;

      ctx.lineCap = "round"; ctx.lineJoin = "round";
      for (const [width, a] of [[7, 0.1], [1.6, 0.9]] as const) {
        ctx.strokeStyle = `rgba(${SIGNAL},${a * alpha})`; ctx.lineWidth = width;
        ctx.beginPath(); ctx.moveTo(pts[0].x, pts[0].y);
        for (let i = 1; i < pts.length; i++) {
          if (cum[i] <= reached) { ctx.lineTo(pts[i].x, pts[i].y); continue; }
          const k = (reached - cum[i - 1]) / (cum[i] - cum[i - 1]);
          if (k > 0) ctx.lineTo(pts[i - 1].x + (pts[i].x - pts[i - 1].x) * k, pts[i - 1].y + (pts[i].y - pts[i - 1].y) * k);
          break;
        }
        ctx.stroke();
      }
      pts.forEach((pt, i) => {
        if (reached < cum[i]) return;
        const last = i === pts.length - 1;
        const since = clamp((reached - cum[i]) / (total * 0.18 + 1), 0, 1);
        ctx.fillStyle = `rgba(${CORE},${alpha})`; ctx.beginPath(); ctx.arc(pt.x, pt.y, last ? 4.2 : 2.6, 0, 6.2832); ctx.fill();
        ctx.strokeStyle = `rgba(${SIGNAL},${(1 - since) * 0.8 * alpha})`; ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.arc(pt.x, pt.y, 5 + since * 18, 0, 6.2832); ctx.stroke();
        if (last && head >= 1) { // the target keeps a slow pulse for as long as the trace is held
          const beat = (t * 0.9) % 1;
          ctx.strokeStyle = `rgba(${SIGNAL},${0.65 * alpha})`; ctx.beginPath(); ctx.arc(pt.x, pt.y, 11, 0, 6.2832); ctx.stroke();
          ctx.strokeStyle = `rgba(${SIGNAL},${(1 - beat) * 0.45 * alpha})`; ctx.beginPath(); ctx.arc(pt.x, pt.y, 11 + beat * 22, 0, 6.2832); ctx.stroke();
        }
      });
    };

    const frame = (ms: number) => {
      const t = ms / 1000;
      const dt = Math.min(0.05, last ? t - last : 0.016);
      last = t;
      const m = modeRef.current;
      speed += ((m === "busy" ? 1.1 : m === "denied" ? 0.03 : 0.35) - speed) * Math.min(1, dt * 3);
      camTarget = pointerX * 0.35 + Math.sin(t * 0.11) * 0.14;
      camX += (camTarget - camX) * Math.min(1, dt * 2.5);
      for (let i = 0; i < hosts.length; i++) {
        const p = hosts[i];
        p.z -= speed * dt;
        if (p.z < NEAR || Math.abs(place(p).x - w / 2) > w * 0.7) {
          if (hunt?.chain.includes(p)) hunt = null;
          hosts[i] = spawn(FAR - Math.random() * 2);
        }
      }
      if (hunt && t - hunt.t0 > hunt.draw + hunt.hold + hunt.fade) { hunt = null; nextHunt = t + (m === "busy" ? 0.25 : 1.4 + Math.random() * 1.6); }
      if (!hunt && m !== "denied" && t >= nextHunt) { hunt = plan(t, m === "busy"); if (!hunt) nextHunt = t + 0.5; }
      drawHosts(t);
      if (hunt) drawHunt(hunt, t);
      raf = requestAnimationFrame(frame);
    };

    const stillFrame = () => { // reduced motion: one composed frame, the trace held at its target
      for (let tries = 0; tries < 8 && !hunt; tries++) hunt = plan(0, false);
      drawHosts(0);
      if (hunt) { hunt.t0 = -hunt.draw - 0.01; drawHunt(hunt, 0); }
    };

    const onPointer = (e: PointerEvent) => { pointerX = e.clientX / Math.max(1, window.innerWidth) - 0.5; };
    const onResize = () => { resize(); if (still) stillFrame(); };
    resize();
    const observer = new ResizeObserver(onResize);
    observer.observe(canvas);
    if (still) stillFrame();
    else {
      window.addEventListener("pointermove", onPointer, { passive: true });
      nextHunt = performance.now() / 1000 + 1.2;
      raf = requestAnimationFrame(frame);
    }
    return () => { cancelAnimationFrame(raf); observer.disconnect(); window.removeEventListener("pointermove", onPointer); };
  }, []);

  return <canvas ref={ref} aria-hidden="true" className="absolute inset-0 h-full w-full animate-scene-in" />;
}
