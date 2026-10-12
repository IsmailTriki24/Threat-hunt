"use client";
import "maplibre-gl/dist/maplibre-gl.css";
import { LngLatBounds, Map as MapLibre, Marker, NavigationControl, Popup, type GeoJSONSource, type MapGeoJSONFeature } from "maplibre-gl";
import { useEffect, useRef } from "react";
import {
  arcPoints, choroplethExpression, fmtInt, LAYER_COLOR, markerRadius, SEVERITY_COLOR, SEVERITIES,
  type CountryRow, type Flow, type Home, type Layer, type MapMarker,
} from "@/lib/threat-map";

export interface CanvasProps {
  layer: Layer;
  markers: MapMarker[];
  countries: CountryRow[];
  flows: Flow[];
  home: Home | null;
  showFlows: boolean;
  animate: boolean;
  selectedIp: string | null;
  fitNonce: number;
  onSelect: (ip: string) => void;
  onCountry: (iso: string) => void;
  onFailure?: (message: string) => void;
}

interface PointGeom { coordinates: [number, number] }
// Disputed/unrecognised territories in the boundary file have an empty ISO code, so "no country" must not be "".
const NO_COUNTRY = "--";
const EMPTY = { type: "FeatureCollection", features: [] } as const;
const FLOW_COLOR = { inbound: "#f0883e", outbound: "#39c5cf", external: "#8b949e" } as const;
// Offline by design: no tile server, no glyph server. The page's CSP only allows same-origin requests, and a SOC console
// should not leak which regions an analyst is looking at to a third-party tile provider.
const STYLE = { version: 8 as const, sources: {}, layers: [{ id: "ocean", type: "background" as const, paint: { "background-color": "#0a1018" } }] };

function markerCollection(markers: MapMarker[], layer: Layer) {
  const max = Math.max(0, ...markers.map((m) => m.weight));
  return {
    type: "FeatureCollection" as const,
    features: markers.filter((m) => m.geo?.lat != null && m.geo?.lon != null).map((m) => ({
      type: "Feature" as const,
      geometry: { type: "Point" as const, coordinates: [m.geo!.lon as number, m.geo!.lat as number] },
      properties: {
        ip: m.ip, sev: SEVERITIES.indexOf(m.severity), color: SEVERITY_COLOR[m.severity], radius: markerRadius(m.weight, max), weight: m.weight,
        country: m.geo?.country_name ?? "", city: m.geo?.city ?? "", org: m.geo?.org ?? "",
        corr: m.layers.includes("correlated") ? 1 : 0, layer,
      },
    })),
  };
}

function flowCollection(flows: Flow[]) {
  const max = Math.max(1, ...flows.map((f) => f.events));
  return {
    type: "FeatureCollection" as const,
    features: flows.map((f) => ({
      type: "Feature" as const,
      geometry: { type: "LineString" as const, coordinates: arcPoints([f.src.lon, f.src.lat], [f.dst.lon, f.dst.lat]) },
      properties: { color: FLOW_COLOR[f.direction], width: 0.8 + 2.2 * Math.sqrt(f.events / max), dir: f.direction, events: f.events, src: f.src.ip, dst: f.dst.ip },
    })),
  };
}

/** The map. It is created once; every prop change after that only swaps source data / paint values, and every event handler is
 *  registered exactly once and reads the latest callbacks through a ref (so re-renders cannot duplicate or leak handlers). */
export default function ThreatMapCanvas(props: CanvasProps) {
  const host = useRef<HTMLDivElement>(null);
  const mapRef = useRef<MapLibre | null>(null);
  const ready = useRef(false);
  const latest = useRef(props);
  latest.current = props;
  const labels = useRef(new Map<number, Marker>());

  // ---- create once ---------------------------------------------------------------------------------------
  useEffect(() => {
    if (!host.current) return;
    let map: MapLibre;
    try {
      map = new MapLibre({ container: host.current, style: STYLE, bounds: [[-168, -52], [190, 76]], fitBoundsOptions: { padding: 8 }, minZoom: 0.8, maxZoom: 9, renderWorldCopies: true, attributionControl: false, dragRotate: false, pitchWithRotate: false });
    } catch (e) {
      latest.current.onFailure?.(e instanceof Error ? e.message : "The map could not start (WebGL is unavailable).");
      return;
    }
    mapRef.current = map;
    map.touchZoomRotate.disableRotation();
    map.addControl(new NavigationControl({ showCompass: false }), "top-right");
    const popup = new Popup({ closeButton: false, closeOnClick: false, offset: 10, className: "tm-popup" });
    let hoverIso = NO_COUNTRY;

    map.on("error", (e) => { if (!ready.current) latest.current.onFailure?.(e.error?.message ?? "Map failed to load"); });
    map.on("load", () => {
      map.addSource("countries", { type: "geojson", data: "/geo/countries.geojson", promoteId: "iso" });
      map.addSource("markers", { type: "geojson", data: EMPTY, cluster: true, clusterRadius: 46, clusterMaxZoom: 5, clusterProperties: { maxSev: ["max", ["get", "sev"]], weight: ["+", ["get", "weight"]] } });
      map.addSource("arcs", { type: "geojson", data: EMPTY });
      map.addSource("home", { type: "geojson", data: EMPTY });
      map.addLayer({ id: "country-fill", type: "fill", source: "countries", paint: { "fill-color": "#121a24", "fill-opacity": 1 } });
      map.addLayer({ id: "country-line", type: "line", source: "countries", paint: { "line-color": "#2a3544", "line-width": 0.6 } });
      map.addLayer({ id: "country-hover", type: "line", source: "countries", filter: ["==", ["get", "iso"], NO_COUNTRY], paint: { "line-color": "#c9d1d9", "line-width": 1.4 } });
      map.addLayer({ id: "arcs", type: "line", source: "arcs", layout: { "line-cap": "round" }, paint: { "line-color": ["get", "color"], "line-width": ["get", "width"], "line-opacity": 0.55, "line-dasharray": [1, 0] } });
      map.addLayer({ id: "home", type: "circle", source: "home", paint: { "circle-radius": 6, "circle-color": "#0a1018", "circle-stroke-color": "#c9d1d9", "circle-stroke-width": 2 } });
      map.addLayer({ id: "cluster", type: "circle", source: "markers", filter: ["has", "point_count"], paint: {
        "circle-color": ["step", ["get", "maxSev"], SEVERITY_COLOR.info, 1, SEVERITY_COLOR.low, 2, SEVERITY_COLOR.medium, 3, SEVERITY_COLOR.high, 4, SEVERITY_COLOR.critical],
        "circle-opacity": 0.28, "circle-stroke-width": 1.5, "circle-stroke-color": ["step", ["get", "maxSev"], SEVERITY_COLOR.info, 1, SEVERITY_COLOR.low, 2, SEVERITY_COLOR.medium, 3, SEVERITY_COLOR.high, 4, SEVERITY_COLOR.critical],
        "circle-radius": ["step", ["get", "point_count"], 13, 10, 17, 50, 22, 200, 28],
      } });
      map.addLayer({ id: "halo", type: "circle", source: "markers", filter: ["all", ["!", ["has", "point_count"]], ["==", ["get", "corr"], 1]], paint: { "circle-radius": ["+", ["get", "radius"], 7], "circle-color": "#f85149", "circle-opacity": 0.16, "circle-blur": 0.6 } });
      map.addLayer({ id: "point", type: "circle", source: "markers", filter: ["!", ["has", "point_count"]], paint: {
        "circle-radius": ["get", "radius"], "circle-color": ["get", "color"], "circle-opacity": 0.82, "circle-stroke-width": 1.25, "circle-stroke-color": "#0a1018",
      } });
      map.addLayer({ id: "selected", type: "circle", source: "markers", filter: ["==", ["get", "ip"], ""], paint: { "circle-radius": ["+", ["get", "radius"], 5], "circle-color": "rgba(0,0,0,0)", "circle-stroke-color": "#ffffff", "circle-stroke-width": 2 } });
      ready.current = true;
      apply();
    });

    const labelMarkers = labels.current;
    const clusterLabels = () => {
      if (!ready.current) return;
      const seen = new Set<number>();
      for (const f of map.querySourceFeatures("markers", { filter: ["has", "point_count"] }).slice(0, 400)) {
        const id = Number(f.properties?.cluster_id);
        if (seen.has(id) || seen.size >= 150) continue;
        seen.add(id);
        const [lon, lat] = (f.geometry as unknown as PointGeom).coordinates;
        let m = labels.current.get(id);
        if (!m) {
          const el = document.createElement("div");
          el.className = "tm-cluster";
          el.setAttribute("aria-hidden", "true");
          m = new Marker({ element: el, anchor: "center" }).setLngLat([lon, lat]).addTo(map);
          labels.current.set(id, m);
        } else m.setLngLat([lon, lat]);
        m.getElement().textContent = fmtInt(Number(f.properties?.point_count));
      }
      for (const [id, m] of labels.current) if (!seen.has(id)) { m.remove(); labels.current.delete(id); }
    };
    map.on("render", () => { if (ready.current && map.isSourceLoaded("markers")) clusterLabels(); });

    map.on("click", "cluster", (e) => {
      const f = e.features?.[0] as MapGeoJSONFeature | undefined;
      if (!f) return;
      void (map.getSource("markers") as GeoJSONSource).getClusterExpansionZoom(Number(f.properties.cluster_id)).then((z) => {
        map.easeTo({ center: (f.geometry as unknown as PointGeom).coordinates, zoom: z + 0.2, duration: 450 });
      });
    });
    map.on("click", "point", (e) => { const ip = e.features?.[0]?.properties?.ip; if (typeof ip === "string") latest.current.onSelect(ip); });
    map.on("click", "country-fill", (e) => {
      if (map.queryRenderedFeatures(e.point, { layers: ["point", "cluster"] }).length) return; // markers win over the country underneath
      const iso = e.features?.[0]?.properties?.iso;
      if (typeof iso === "string" && iso) latest.current.onCountry(iso);
    });
    for (const l of ["point", "cluster"]) {
      map.on("mouseenter", l, () => { map.getCanvas().style.cursor = "pointer"; });
      map.on("mouseleave", l, () => { map.getCanvas().style.cursor = ""; popup.remove(); });
    }
    map.on("mousemove", "point", (e) => {
      const p = e.features?.[0]?.properties;
      if (!p) return;
      const root = document.createElement("div");
      const strong = document.createElement("strong");
      strong.textContent = String(p.ip); // textContent only: feed-derived strings are never interpreted as markup
      const sub = document.createElement("div");
      sub.textContent = [p.city, p.country].filter(Boolean).join(", ") || "location unknown";
      sub.className = "tm-sub";
      root.append(strong, sub);
      popup.setLngLat(e.lngLat).setDOMContent(root).addTo(map);
    });
    map.on("mousemove", "country-fill", (e) => {
      const iso = String(e.features?.[0]?.properties?.iso || NO_COUNTRY);
      if (iso !== hoverIso) { hoverIso = iso; map.setFilter("country-hover", ["==", ["get", "iso"], iso]); }
    });
    map.on("mouseleave", "country-fill", () => { hoverIso = NO_COUNTRY; map.setFilter("country-hover", ["==", ["get", "iso"], NO_COUNTRY]); });

    const ro = new ResizeObserver(() => map.resize());
    ro.observe(host.current);

    function apply() {
      const p = latest.current;
      (map.getSource("markers") as GeoJSONSource).setData(markerCollection(p.markers, p.layer));
      map.setPaintProperty("country-fill", "fill-color", choroplethExpression(p.countries, p.layer) as never);
      (map.getSource("arcs") as GeoJSONSource).setData(p.showFlows ? flowCollection(p.flows) : EMPTY);
      (map.getSource("home") as GeoJSONSource).setData(p.showFlows && p.home ? { type: "FeatureCollection", features: [{ type: "Feature", geometry: { type: "Point", coordinates: [p.home.lon, p.home.lat] }, properties: {} }] } : EMPTY);
      map.setPaintProperty("point", "circle-stroke-color", p.layer === "intelligence" ? LAYER_COLOR.intelligence : "#0a1018");
      map.setPaintProperty("point", "circle-opacity", p.layer === "intelligence" ? 0.6 : 0.85);
      map.setPaintProperty("point", "circle-stroke-width", p.layer === "intelligence" ? 2 : 1.25);
      map.setFilter("selected", ["==", ["get", "ip"], p.selectedIp ?? ""]);
    }
    (map as unknown as { __apply: () => void }).__apply = apply;

    return () => {
      ready.current = false;
      ro.disconnect();
      popup.remove();
      for (const m of labelMarkers.values()) m.remove();
      labelMarkers.clear();
      map.remove();
      mapRef.current = null;
    };
  }, []);

  // ---- data / paint updates ---------------------------------------------------------------------------------
  const { markers, countries, flows, home, showFlows, layer, selectedIp } = props;
  useEffect(() => {
    const m = mapRef.current as (MapLibre & { __apply?: () => void }) | null;
    if (m && ready.current) m.__apply?.();
  }, [markers, countries, flows, home, showFlows, layer, selectedIp]);

  // ---- subtle flow animation (opt-in; never under prefers-reduced-motion) -----------------------------------
  useEffect(() => {
    const m = mapRef.current;
    if (!m || !ready.current) return;
    if (!props.animate || !showFlows || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      if (m.getLayer("arcs")) m.setPaintProperty("arcs", "line-dasharray", [1, 0]);
      return;
    }
    const frames: Array<[number, number, number]> = [[0, 4, 3], [0.5, 4, 2.5], [1, 4, 2], [1.5, 4, 1.5], [2, 4, 1], [2.5, 4, 0.5], [3, 4, 0]];
    let i = 0;
    const id = window.setInterval(() => {
      i = (i + 1) % frames.length;
      const [a, b, c] = frames[i];
      if (m.getLayer("arcs")) m.setPaintProperty("arcs", "line-dasharray", [a || 0.01, b, c || 0.01]);
    }, 140);
    return () => { window.clearInterval(id); if (m.getLayer("arcs")) m.setPaintProperty("arcs", "line-dasharray", [1, 0]); };
  }, [props.animate, showFlows, flows]);

  // ---- fit to the shown markers on request ------------------------------------------------------------------
  useEffect(() => {
    const m = mapRef.current;
    if (!m || !ready.current || props.fitNonce === 0) return;
    const pts = latest.current.markers.filter((x) => x.geo?.lat != null && x.geo?.lon != null);
    if (!pts.length) { m.fitBounds([[-168, -52], [190, 76]], { padding: 8, duration: 500 }); return; }
    const b = new LngLatBounds();
    pts.forEach((x) => b.extend([x.geo!.lon as number, x.geo!.lat as number]));
    m.fitBounds(b, { padding: 60, maxZoom: 5, duration: 600 });
  }, [props.fitNonce]);

  // Inline style, not a class: maplibre-gl.css sets `.maplibregl-map { position: relative }`, which would collapse an `absolute` class to 0 height.
  return <div ref={host} style={{ position: "absolute", inset: 0 }} role="application" aria-label="Interactive world threat map" />;
}
