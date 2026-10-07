# ADR 0001 — Backend stack: FastAPI + SQLAlchemy 2 (async) + Pydantic

**Status:** accepted · **Date:** 2026-10-07

## Context
The brief lists "django, Pydantic, SQLAlchemy" and also "FastAPI" in Milestone 1. Django's ORM and SQLAlchemy
are alternatives, not complements, and Django's sync-first model fits poorly with an OpenSearch/Redis-heavy,
I/O-bound API.

## Decision
FastAPI + Pydantic v2 + SQLAlchemy 2.x (asyncio, asyncpg) + Alembic. Django is not used.

## Consequences
* One typed validation layer (Pydantic) for API, connectors and the canonical event model.
* Authorization is explicit (`require(Permission)` dependencies) rather than framework-implicit; every
  route's policy is visible at the route definition and covered by tests.
* We implement a few things Django ships (admin, auth) ourselves; the auth surface is small and tested.
