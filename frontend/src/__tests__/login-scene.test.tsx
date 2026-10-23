import { render } from "@testing-library/react";
import { LoginScene } from "@/components/login-scene";

/** A 2D context whose every method is a no-op, with a spy on the calls the scene must make. */
const fakeContext = () => {
  const calls: string[] = [];
  const ctx = new Proxy({} as Record<string, unknown>, {
    get: (t, k: string) => (k in t ? t[k] : (...a: unknown[]) => { calls.push(k); void a; }),
    set: (t, k: string, v) => { t[k] = v; return true; },
  });
  return { ctx, calls };
};

let reduce = false;
beforeEach(() => {
  reduce = false;
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
  vi.stubGlobal("matchMedia", () => ({ matches: reduce, addEventListener() {}, removeEventListener() {} }));
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it("is decorative and survives a browser without canvas support", () => {
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(null);
  const raf = vi.spyOn(window, "requestAnimationFrame");
  const { container } = render(<LoginScene mode="idle" />);
  expect(container.querySelector("canvas")).toHaveAttribute("aria-hidden", "true");
  expect(raf).not.toHaveBeenCalled();
});

it("animates, and stops its loop when the page goes away", () => {
  const { ctx } = fakeContext();
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
  const raf = vi.spyOn(window, "requestAnimationFrame").mockReturnValue(7);
  const cancel = vi.spyOn(window, "cancelAnimationFrame");
  const { unmount } = render(<LoginScene mode="idle" />);
  expect(raf).toHaveBeenCalled();
  unmount();
  expect(cancel).toHaveBeenCalledWith(7);
});

it("draws one still frame and never starts a loop when the user asks for reduced motion", () => {
  reduce = true;
  const { ctx, calls } = fakeContext();
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
  const raf = vi.spyOn(window, "requestAnimationFrame");
  render(<LoginScene mode="idle" />);
  expect(raf).not.toHaveBeenCalled();
  expect(calls).toContain("clearRect");
  expect(calls).toContain("arc"); // the hosts were drawn
});
