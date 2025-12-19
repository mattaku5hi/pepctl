# PEPCTL Admin API Documentation

## Table of Contents
- [Implemented API (Current)](#implemented-api-current)
- [Overview](#overview)
- [Authentication](#authentication)
- [Base URLs and Versioning](#base-urls-and-versioning)
- [Response Formats](#response-formats)
- [Policy Management API](#policy-management-api)
- [Error Handling](#error-handling)
- [Example Workflows](#example-workflows)

## Implemented API (Current)

The current implementation exposes a single HTTP server (MetricsServer) on the port configured by `server.metrics_port` (default `9090`).

Base URL:
```
http://<host>:<metrics_port>
```

Implemented endpoints:
- `GET /health` — liveness probe.
- `GET /stats` — JSON statistics snapshot.
- `GET /metrics` — Prometheus exposition format.
- `GET /policies` — export policies as JSON.
- `POST /policies` — replace/load policies from JSON request body.
- `DELETE /policies?id=<policy_id>` or `DELETE /policies` with JSON body `{"id":"..."}` — remove a single policy.
- `POST /reset` — reset daemon/eBPF counters (where supported).

## Overview

The PEPCTL HTTP API provides a small set of endpoints for policy management and observability.

### Key Features
- **Policy Management**: Replace/export/remove policies at runtime
- **Health**: Liveness endpoint
- **Statistics**: JSON stats snapshot
- **Metrics**: Prometheus metrics endpoint

### API Principles
- **RESTful Design**: Standard HTTP methods and status codes
- **JSON Format**: All requests and responses use JSON
- **Idempotent Operations**: Safe to retry operations
- **Atomic Updates**: Policy changes are applied atomically
- **Error Transparency**: Detailed error messages and codes

## Authentication

The current implementation does not provide application-layer authentication/authorization.

### Future Authentication Methods
- **API Keys**: Token-based authentication
- **TLS Client Certificates**: Mutual TLS authentication
- **JWT Tokens**: JSON Web Token support

## Base URLs and Versioning

### Base URL
```
http://localhost:<metrics_port>/
```

### Versioning Strategy
- The current implementation does not use URL versioning.

## Response Formats

### Standard Response Structure

The current implementation returns:
- JSON objects for `/health`, `/stats`, `/policies` (except `/metrics`).
- Plain text for `/metrics`.

#### Success Response
```json
{
  "status": "success",
  "timestamp": "2025-06-16T10:30:00Z"
}
```

#### Error Response
```json
{
  "error": "Policy not found"
}
```

### HTTP Status Codes
| Code | Meaning | Usage |
|------|---------|--------|
| 200 | OK | Successful GET, PUT requests |
| 201 | Created | Successful POST requests |
| 204 | No Content | Successful DELETE requests |
| 400 | Bad Request | Invalid request format/data |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 422 | Unprocessable Entity | Validation errors |
| 500 | Internal Server Error | Server-side errors |

## Policy Management API

### Policy Object Structure

```json
{
  "id": "unique_policy_identifier",
  "action": "ALLOW|LOG_ONLY|BLOCK|RATE_LIMIT",
  "src": {
    "ip": "0.0.0.0",
    "port": 0,
    "protocol": "ANY"
  },
  "dst": {
    "ip": "0.0.0.0",
    "port": 0,
    "protocol": "ANY"
  },
  "rate_limit_bps": 1000000,
  "created_at": "2025-06-16T10:30:00Z",
  "expires_at": "2025-06-16T11:30:00Z"
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique policy identifier |
| `action` | enum | Yes | `ALLOW`, `LOG_ONLY`, `BLOCK`, or `RATE_LIMIT` |
| `src` | object | Yes | Source selector (`ip`, `port`, `protocol`) |
| `dst` | object | Yes | Destination selector (`ip`, `port`, `protocol`) |
| `rate_limit_bps` | integer | No | Bytes per second (for `RATE_LIMIT` action) |
| `created_at` | string | No | ISO timestamp |
| `expires_at` | string | No | ISO timestamp |

### Get All Policies

```http
GET /policies
```

#### Example Request
```bash
curl "http://localhost:9090/policies"
```

#### Example Response
```json
[
  {
    "id": "allow_ssh",
    "action": "ALLOW",
    "src": {"ip":"0.0.0.0","port":0,"protocol":"ANY"},
    "dst": {"ip":"0.0.0.0","port":22,"protocol":"TCP"}
  }
]
```

### Replace / Load Policies

```http
POST /policies
Content-Type: application/json
```

Notes:
- The request body must be a JSON array of policy objects.
- The load operation replaces the current policy set.

Example:
```bash
curl -X POST "http://localhost:9090/policies" \
  -H "Content-Type: application/json" \
  -d @policies.json
```

### Remove a Single Policy

```http
DELETE /policies?id={policy_id}
```

Example (query parameter):
```bash
curl -X DELETE "http://localhost:9090/policies?id=allow_ssh"
```

Example (JSON body):
```bash
curl -X DELETE "http://localhost:9090/policies" \
  -H "Content-Type: application/json" \
  -d '{"id":"allow_ssh"}'
```

## System & Observability

### Health

```http
GET /health
```

Response example:
```json
{"status":"ok","timestamp":"...","uptime_seconds":123}
```

### Statistics

```http
GET /stats
```

### Prometheus Metrics

```http
GET /metrics
```

### Reset Counters

```http
POST /reset
```

## Error Handling

The current implementation uses standard HTTP status codes and returns a small JSON object with an `error` field.

Common cases:
- `400 Bad Request` — invalid JSON / missing required fields
- `404 Not Found` — policy not found (for delete)
- `405 Method Not Allowed` — wrong HTTP method for the endpoint
- `503 Service Unavailable` — dependencies not available (e.g. metrics reset without daemon metrics)

Example:
```json
{"error":"Method not allowed"}
```

## Example Workflows

### 1. Load policies from a file

```bash
curl -X POST "http://localhost:9090/policies" \
  -H "Content-Type: application/json" \
  -d @policies.json
```

### 2. Delete a policy by id

```bash
curl -X DELETE "http://localhost:9090/policies?id=allow_ssh"
```

### 3. Reset counters

```bash
curl -X POST "http://localhost:9090/reset"
```