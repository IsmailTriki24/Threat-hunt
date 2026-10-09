"use client";
import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props { children: ReactNode; fallback: (reset: () => void) => ReactNode; onError?: (e: Error) => void }

/** Keeps a rendering failure in one panel from taking the whole page down ("Application error"). */
export class ErrorBoundary extends Component<Props, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error("UI error", error, info.componentStack); this.props.onError?.(error); }
  render() { return this.state.failed ? this.props.fallback(() => this.setState({ failed: false })) : this.props.children; }
}
