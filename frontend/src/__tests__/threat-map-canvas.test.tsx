import { render } from "@testing-library/react";
import type { CanvasProps } from "@/components/threat-map-canvas";
import type { MapMarker } from "@/lib/threat-map";

interface FakeMapShape {
  handlers: Array<{ ev: string; layer?: string; fn: (e: unknown) => void }>;
  removed: boolean;
  setFilter: ReturnType<typeof vi.fn>;
  queryRenderedFeatures: () => never[];
  getSource: (id: string) => { data: unknown; setData: ReturnType<typeof vi.fn> } | undefined;
  fire: (ev: string, payload?: unknown, layer?: string) => void;
}
const { created, state, FakeMap } = vi.hoisted(() => {
  type Handler = (e: unknown) => void;
  const created: FakeMapShape[] = [];
  const state = { failConstruct: false };

  class FakeSource { data: unknown = null; setData = vi.fn((d: unknown) => { this.data = d; }); getClusterExpansionZoom = vi.fn(async () => 4); }
  class FakeMap {
    handlers: Array<{ ev: string; layer?: string; fn: Handler }> = [];
    sources = new Map<string, FakeSource>();
    layers = new Set<string>();
    paint = new Map<string, unknown>();
    removed = false;
    touchZoomRotate = { disableRotation: vi.fn() };
    constructor() {
      if (state.failConstruct) throw new Error("WebGL is not supported");
      created.push(this as unknown as FakeMapShape);
    }
    on(ev: string, a: string | Handler, b?: Handler) { this.handlers.push(typeof a === "string" ? { ev, layer: a, fn: b! } : { ev, fn: a }); return this; }
    addControl = vi.fn();
    addSource(id: string) { this.sources.set(id, new FakeSource()); }
    addLayer(l: { id: string }) { this.layers.add(l.id); }
    getSource(id: string) { return this.sources.get(id); }
    getLayer(id: string) { return this.layers.has(id) ? {} : undefined; }
    setPaintProperty(l: string, p: string, v: unknown) { this.paint.set(`${l}.${p}`, v); }
    setFilter = vi.fn();
    getCanvas() { return { style: {} as CSSStyleDeclaration }; }
    querySourceFeatures() { return []; }
    queryRenderedFeatures() { return []; }
    isSourceLoaded() { return true; }
    easeTo = vi.fn(); fitBounds = vi.fn(); resize = vi.fn();
    remove() { this.removed = true; }
    fire(ev: string, payload?: unknown, layer?: string) { this.handlers.filter((h) => h.ev === ev && h.layer === layer).forEach((h) => h.fn(payload)); }
  }

  return { created, state, FakeMap };
});
vi.mock("maplibre-gl/dist/maplibre-gl.css", () => ({}));
vi.mock("maplibre-gl", () => ({
  Map: FakeMap,
  Marker: class { setLngLat() { return this; } addTo() { return this; } remove() {} getElement() { return document.createElement("div"); } },
  Popup: class { setLngLat() { return this; } setDOMContent() { return this; } addTo() { return this; } remove() {} },
  NavigationControl: class {},
  LngLatBounds: class { extend() { return this; } },
}));
vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });

import ThreatMapCanvas from "@/components/threat-map-canvas";

const m = (ip: string, lat: number | null = 10, lon: number | null = 20): MapMarker => ({
  ip, geo: { country: "DE", country_name: "Germany", continent: "EU", city: "Berlin", region: "", lat, lon, asn: null, org: "" }, layers: ["intelligence"], severity: "high",
  weight: 5, last_seen: null, intel: null, observed: null, hunt_matches: 0,
});
const props = (o: Partial<CanvasProps> = {}): CanvasProps => ({
  layer: "intelligence", markers: [m("1.1.1.1")], countries: [], flows: [], home: null, showFlows: false, animate: false, selectedIp: null, fitNonce: 0,
  onSelect: vi.fn(), onCountry: vi.fn(), ...o,
});
beforeEach(() => { created.length = 0; state.failConstruct = false; });

it("creates the map once and registers every handler exactly once, however often props change", () => {
  const { rerender } = render(<ThreatMapCanvas {...props()} />);
  const map = created[0];
  map.fire("load");
  const counts = () => map.handlers.map((h) => `${h.ev}:${h.layer ?? ""}`).sort().join("|");
  const before = counts();
  for (let i = 0; i < 5; i++) rerender(<ThreatMapCanvas {...props({ markers: [m(`2.2.2.${i}`)], selectedIp: `2.2.2.${i}` })} />);
  expect(created).toHaveLength(1);
  expect(counts()).toBe(before);
  for (const key of ["click:point", "click:cluster", "click:country-fill", "mousemove:point"]) expect(before.split("|").filter((x) => x === key)).toHaveLength(1);
});

it("pushes new data into the sources instead of rebuilding the map", () => {
  const { rerender } = render(<ThreatMapCanvas {...props()} />);
  const map = created[0];
  map.fire("load");
  const src = map.getSource("markers")!;
  const calls = src.setData.mock.calls.length;
  rerender(<ThreatMapCanvas {...props({ markers: [m("3.3.3.3"), m("4.4.4.4"), m("5.5.5.5", null, null)] })} />);
  expect(src.setData.mock.calls.length).toBeGreaterThan(calls);
  const fc = src.data as { features: Array<{ properties: { ip: string }; geometry: { coordinates: number[] } }> };
  expect(fc.features.map((f) => f.properties.ip)).toEqual(["3.3.3.3", "4.4.4.4"]); // an address without coordinates is never invented a place
  expect(fc.features[0].geometry.coordinates).toEqual([20, 10]); // [lon, lat]
  expect(map.setFilter).toHaveBeenLastCalledWith("selected", ["==", ["get", "ip"], ""]);
  rerender(<ThreatMapCanvas {...props({ selectedIp: "4.4.4.4" })} />);
  expect(map.setFilter).toHaveBeenLastCalledWith("selected", ["==", ["get", "ip"], "4.4.4.4"]);
});

it("draws arcs and the home marker only when connections are shown", () => {
  const flow = { src: { ip: "8.8.8.8", class: "public", lat: 37, lon: -122, country: "US", city: "" }, dst: { ip: "10.0.0.1", class: "private", lat: 36.8, lon: 10.2, country: "", city: "HQ" }, direction: "inbound" as const, events: 3, first_seen: null, last_seen: null, severity: "low" as const, ports: [443], sources: [], protocols: [] };
  const home = { lat: 36.8, lon: 10.2, label: "HQ" };
  const { rerender } = render(<ThreatMapCanvas {...props({ layer: "observed", flows: [flow], home, showFlows: false })} />);
  const map = created[0];
  map.fire("load");
  const arcs = () => (map.getSource("arcs")!.data as { features: unknown[] }).features.length;
  expect(arcs()).toBe(0);
  rerender(<ThreatMapCanvas {...props({ layer: "observed", flows: [flow], home, showFlows: true })} />);
  expect(arcs()).toBe(1);
  expect((map.getSource("home")!.data as { features: unknown[] }).features).toHaveLength(1);
});

it("routes clicks to the latest callbacks, and a marker click beats the country underneath", () => {
  const first = props();
  const { rerender } = render(<ThreatMapCanvas {...first} />);
  const map = created[0];
  map.fire("load");
  const second = props();
  rerender(<ThreatMapCanvas {...second} />);
  map.fire("click", { features: [{ properties: { ip: "9.9.9.9" } }] }, "point");
  expect(second.onSelect).toHaveBeenCalledWith("9.9.9.9");
  expect(first.onSelect).not.toHaveBeenCalled();
  map.fire("click", { features: [{ properties: { iso: "FR" } }], point: { x: 1, y: 1 } }, "country-fill");
  expect(second.onCountry).toHaveBeenCalledWith("FR");
  map.queryRenderedFeatures = () => [{}] as never[];
  map.fire("click", { features: [{ properties: { iso: "DE" } }], point: { x: 1, y: 1 } }, "country-fill");
  expect(second.onCountry).toHaveBeenCalledTimes(1);
});

it("never highlights territories that have no ISO code when nothing is hovered", () => {
  render(<ThreatMapCanvas {...props()} />);
  const map = created[0];
  map.fire("load");
  map.fire("mouseleave", {}, "country-fill");
  const filter = JSON.stringify(map.setFilter.mock.calls.at(-1)?.[1]);
  expect(filter).not.toContain('"iso"],""'); // an empty-string sentinel would match Somaliland / N. Cyprus
  map.fire("mousemove", { features: [{ properties: { iso: "" } }] }, "country-fill");
  expect(JSON.stringify(map.setFilter.mock.calls.at(-1)?.[1])).not.toContain('"iso"],""');
});

it("releases the map on unmount", () => {
  const { unmount } = render(<ThreatMapCanvas {...props()} />);
  const map = created[0];
  map.fire("load");
  unmount();
  expect(map.removed).toBe(true);
});

it("reports a failure instead of crashing when WebGL is unavailable", () => {
  state.failConstruct = true;
  const onFailure = vi.fn();
  render(<ThreatMapCanvas {...props({ onFailure })} />);
  expect(onFailure).toHaveBeenCalledWith("WebGL is not supported");
});
