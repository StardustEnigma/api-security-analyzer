# 🛡️ SentinelAPI — API Documentation

> **Version:** 1.0.0  
> **Base URL:** `http://localhost:8080/api`  
> **Content-Type:** `application/json`

SentinelAPI is an automated security vulnerability scanner that tests API endpoints for common security weaknesses and generates structured vulnerability reports with **attack chain visualization** — showing how individual weaknesses can be chained into multi-step exploits.

---

## Table of Contents

- [Health Check](#1-health-check)
- [Full Security Scan](#2-full-security-scan)
- [Attack Chains Only](#3-attack-chains-only)
- [Export Attack Graph (React Flow)](#4-export-attack-graph-react-flow)
- [Data Models](#data-models)
- [Security Scanners](#security-scanners)
- [Attack Chain Detection Rules](#attack-chain-detection-rules)
- [Error Handling](#error-handling)

---

## Endpoints

### 1. Health Check

Check if the API is running.

```
GET /api/health
```

#### Response

| Status | Body |
|--------|------|
| `200 OK` | `SentinelAPI is running` |

#### Example

```bash
curl http://localhost:8080/api/health
```

---

### 2. Full Security Scan

Run all 8 security scanners against a target URL, then analyze the results through the **Attack Chain Visualization Engine** to identify multi-step attack paths.

```
POST /api/scan
```

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targetUrl` | `string` | ✅ | The URL to scan. Must start with `http://` or `https://`. |

```json
{
  "targetUrl": "https://example.com"
}
```

#### Response `200 OK`

Returns a [`VulnerabilityReport`](#vulnerabilityreport) object.

#### Example

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com"}'
```

#### Example Response

```json
{
  "targetUrl": "https://example.com",
  "scanTimestamp": "2026-02-19T14:30:00.000",
  "totalVulnerabilities": 5,
  "severitySummary": {
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 2
  },
  "vulnerabilities": [
    {
      "name": "Missing Security Header: Strict-Transport-Security",
      "severity": "HIGH",
      "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks.",
      "evidence": "Header 'Strict-Transport-Security' was not found in the response.",
      "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    {
      "name": "Missing Security Header: Content-Security-Policy",
      "severity": "MEDIUM",
      "description": "Content-Security-Policy header is missing. This increases risk of XSS attacks.",
      "evidence": "Header 'Content-Security-Policy' was not found in the response.",
      "remediation": "Implement a Content-Security-Policy header with appropriate directives."
    }
  ],
  "scanDurationMs": 4523,
  "attackChainVisualization": {
    "targetUrl": "https://example.com",
    "attackChains": [
      {
        "id": "chain-1",
        "title": "SSL/TLS Weakness → MitM",
        "description": "Weak SSL/TLS configuration allows an attacker to perform man-in-the-middle attacks, amplified by missing HSTS enabling SSL stripping.",
        "nodes": [
          {
            "id": "node-1",
            "label": "No HTTPS",
            "vulnerabilityName": "No HTTPS",
            "category": "SSL_TLS_WEAKNESS",
            "severity": "HIGH",
            "attackerAction": "Exploit weak SSL/TLS configuration",
            "outcome": "Attacker can intercept or downgrade encrypted connections",
            "depth": 0
          },
          {
            "id": "node-2",
            "label": "Missing HSTS",
            "vulnerabilityName": "Missing HSTS",
            "category": "MISSING_HEADER",
            "severity": "HIGH",
            "attackerAction": "Without HSTS, browsers don't enforce HTTPS",
            "outcome": "SSL stripping attack becomes possible",
            "depth": 1
          },
          {
            "id": "node-3",
            "label": "⚠ IMPACT: Man-in-the-Middle",
            "vulnerabilityName": "Man-in-the-Middle",
            "category": "OTHER",
            "severity": "CRITICAL",
            "attackerAction": "Intercept and modify traffic between user and server",
            "outcome": "Full visibility into transmitted data",
            "depth": 2
          }
        ],
        "edges": [
          {
            "from": "node-1",
            "to": "node-2",
            "label": "combined with",
            "description": "Weak TLS + missing HSTS enables SSL stripping",
            "confidence": 0.7
          },
          {
            "from": "node-2",
            "to": "node-3",
            "label": "enables",
            "description": "Downgraded connection allows traffic interception",
            "confidence": 0.8
          }
        ],
        "maxSeverity": "CRITICAL",
        "riskScore": 75.0,
        "chainLength": 3,
        "impact": "Traffic interception and potential data exposure",
        "priorityRemediation": "Upgrade to TLS 1.2+ with strong cipher suites and add HSTS header"
      }
    ],
    "totalChains": 1,
    "maxRiskScore": 75.0,
    "overallThreatLevel": "HIGH",
    "allNodes": [ "..." ],
    "allEdges": [ "..." ],
    "chainSeverityDistribution": {
      "CRITICAL": 1
    },
    "topRemediation": "Upgrade to TLS 1.2+ with strong cipher suites and add HSTS header",
    "chainsBlockedByTopRemediation": 1
  }
}
```

---

### 3. Attack Chains Only

Run the same full scan but return **only** the attack chain visualization graph data. Useful when the frontend only needs the graph for rendering.

```
POST /api/scan/attack-chains
```

#### Request Body

Same as [Full Security Scan](#2-full-security-scan).

```json
{
  "targetUrl": "https://example.com"
}
```

#### Response `200 OK`

Returns an [`AttackChainVisualization`](#attackchainvisualization) object directly (not wrapped in a report).

#### Example

```bash
curl -X POST http://localhost:8080/api/scan/attack-chains \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com"}'
```

---

### 4. Export Attack Graph (React Flow)

Run a full scan and return the attack chain graph in a **React Flow-compatible format**. The response contains `nodes[]` and `edges[]` arrays ready to pass directly into `<ReactFlow />`, plus layout metadata, color maps, statistics, and per-chain summaries with node/edge IDs for interactive highlighting.

```
POST /api/scan/export-graph
```

#### Request Body

Same as [Full Security Scan](#2-full-security-scan).

```json
{
  "targetUrl": "https://jsonplaceholder.typicode.com"
}
```

#### Response `200 OK`

Returns a [`GraphExportResponse`](#graphexportresponse) object.

#### React Usage

```jsx
const res = await fetch('/api/scan/export-graph', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ targetUrl: 'https://example.com' })
});
const { nodes, edges, layout, stats, chainSummaries, severityColorMap } = await res.json();

<ReactFlow
  nodes={nodes}
  edges={edges}
  fitView
  defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
/>
```

#### Example Response (abbreviated)

```json
{
  "targetUrl": "https://jsonplaceholder.typicode.com",
  "nodes": [
    {
      "id": "node-1",
      "type": "entry",
      "position": { "x": 0, "y": 0 },
      "data": {
        "label": "Missing Security Headers (5 headers)",
        "vulnerabilityName": "Missing Security Headers (5 headers)",
        "category": "MISSING_HEADER",
        "categoryDisplay": "Missing Security Header",
        "severity": "MEDIUM",
        "attackerAction": "Identify 5 missing security headers via response analysis",
        "outcome": "Application lacks browser-side security controls",
        "depth": 0,
        "chainId": "chain-1",
        "isImpact": false,
        "isEntry": true
      },
      "style": {
        "background": "#FFFDE7",
        "border": "2px solid #FFC400",
        "borderRadius": "12px",
        "padding": "16px",
        "minWidth": "220px",
        "maxWidth": "280px",
        "fontSize": "13px",
        "boxShadow": "0 2px 8px rgba(0,0,0,0.1)"
      },
      "parentId": "chain-1"
    },
    {
      "id": "node-4",
      "type": "impact",
      "position": { "x": 960, "y": 0 },
      "data": {
        "label": "⚠ IMPACT: Weakened Security Posture",
        "severity": "CRITICAL",
        "isImpact": true,
        "isEntry": false
      },
      "style": {
        "border": "3px solid #FF1744",
        "background": "#FFF0F0",
        "fontWeight": "bold"
      },
      "parentId": "chain-1"
    }
  ],
  "edges": [
    {
      "id": "edge-1",
      "source": "node-1",
      "target": "node-2",
      "sourceHandle": "right",
      "targetHandle": "left",
      "type": "smoothstep",
      "animated": true,
      "label": "exposes (80%)",
      "markerEnd": { "type": "arrowclosed", "color": "#FF1744" },
      "style": { "stroke": "#FF1744", "strokeWidth": "2.5" },
      "labelStyle": { "fontSize": "11px", "fontWeight": "600", "fill": "#333" },
      "data": {
        "description": "Missing CSP removes script execution restrictions",
        "confidence": 0.8,
        "confidenceLabel": "High",
        "chainId": "chain-1"
      }
    }
  ],
  "layout": {
    "algorithm": "dagre",
    "direction": "LR",
    "nodeSpacingX": 320,
    "nodeSpacingY": 200,
    "graphWidth": 1280,
    "graphHeight": 520
  },
  "severityColorMap": {
    "CRITICAL": "#FF1744",
    "HIGH": "#FF6D00",
    "MEDIUM": "#FFC400",
    "LOW": "#00E676",
    "INFO": "#448AFF"
  },
  "nodeTypeLegend": {
    "vulnerability": "A discovered vulnerability that serves as an attack step",
    "impact": "The ultimate impact / consequence of the attack chain",
    "entry": "The initial entry point of the attack chain (depth 0)"
  },
  "stats": {
    "totalNodes": 12,
    "totalEdges": 10,
    "totalChains": 3,
    "maxRiskScore": 56.0,
    "overallThreatLevel": "MEDIUM",
    "topRemediation": "Implement all missing security headers...",
    "chainsBlockedByTopRemediation": 2,
    "nodesBySeverity": { "CRITICAL": 3, "MEDIUM": 6, "LOW": 3 },
    "nodesByCategory": { "MISSING_HEADER": 5, "OTHER": 3, "DANGEROUS_HTTP_METHOD": 2, "INFORMATION_DISCLOSURE": 2 }
  },
  "chainSummaries": [
    {
      "chainId": "chain-1",
      "title": "Missing Security Headers → Weakened Defenses → Client-Side Attacks",
      "description": "5 security headers are missing...",
      "riskScore": 56.0,
      "maxSeverity": "CRITICAL",
      "chainLength": 4,
      "impact": "Client-side attacks enabled: script injection, clickjacking, SSL stripping",
      "priorityRemediation": "Implement all missing security headers...",
      "nodeIds": ["node-1", "node-2", "node-3", "node-4"],
      "edgeIds": ["edge-1", "edge-2", "edge-3"]
    }
  ]
}
```

#### Chain Highlighting (React)

Each `chainSummary` includes `nodeIds` and `edgeIds`. Use them to highlight chains on hover/click:

```jsx
const [highlightedChain, setHighlightedChain] = useState(null);

// In sidebar:
chainSummaries.map(chain => (
  <div
    key={chain.chainId}
    onMouseEnter={() => setHighlightedChain(chain)}
    onMouseLeave={() => setHighlightedChain(null)}
  >
    {chain.title} — Risk: {chain.riskScore}
  </div>
));

// Apply styles:
const styledNodes = nodes.map(node => ({
  ...node,
  style: {
    ...node.style,
    opacity: !highlightedChain || highlightedChain.nodeIds.includes(node.id) ? 1 : 0.2
  }
}));
```

---

## Data Models

### `VulnerabilityReport`

Top-level response from the full scan endpoint.

| Field | Type | Description |
|-------|------|-------------|
| `targetUrl` | `string` | The scanned URL |
| `scanTimestamp` | `string` (ISO 8601) | When the scan was performed |
| `totalVulnerabilities` | `integer` | Total number of findings |
| `severitySummary` | `map<Severity, integer>` | Count of findings per severity level |
| `vulnerabilities` | [`Vulnerability[]`](#vulnerability) | All individual findings |
| `scanDurationMs` | `long` | Scan duration in milliseconds |
| `attackChainVisualization` | [`AttackChainVisualization`](#attackchainvisualization) | Attack chain graph and analysis |

---

### `Vulnerability`

A single security finding.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Short identifier (e.g., `"Missing Security Header: X-Frame-Options"`) |
| `severity` | [`Severity`](#severity) | Impact level |
| `description` | `string` | What the vulnerability is and why it matters |
| `evidence` | `string` | Proof found during the scan |
| `remediation` | `string` | How to fix it |

---

### `AttackChainVisualization`

The complete attack chain visualization payload. Contains all discovered chains plus a combined flat graph for rendering.

| Field | Type | Description |
|-------|------|-------------|
| `targetUrl` | `string` | The scanned URL |
| `attackChains` | [`AttackChain[]`](#attackchain) | All discovered attack chains, ordered by risk score (highest first) |
| `totalChains` | `integer` | Number of attack chains found |
| `maxRiskScore` | `double` | Highest risk score across all chains (0–100) |
| `overallThreatLevel` | `string` | One of: `NONE`, `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `allNodes` | [`AttackChainNode[]`](#attackchainnode) | Flat list of ALL nodes across all chains (for unified graph rendering) |
| `allEdges` | [`AttackChainEdge[]`](#attackchainedge) | Flat list of ALL edges across all chains |
| `chainSeverityDistribution` | `map<string, integer>` | Number of chains at each severity tier |
| `topRemediation` | `string` | The single fix that breaks the most chains |
| `chainsBlockedByTopRemediation` | `integer` | How many chains the top fix would neutralize |

---

### `AttackChain`

A complete multi-step attack path — an ordered sequence of exploit steps from initial weakness to high-impact outcome.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique identifier (e.g., `"chain-1"`) |
| `title` | `string` | Short description of the attack scenario |
| `description` | `string` | Narrative explanation of the full attack flow |
| `nodes` | [`AttackChainNode[]`](#attackchainnode) | Ordered steps in this chain |
| `edges` | [`AttackChainEdge[]`](#attackchainedge) | Connections between steps |
| `maxSeverity` | [`Severity`](#severity) | Highest severity reached in this chain |
| `riskScore` | `double` | Composite risk score (0–100) considering severity, confidence, and chain length |
| `chainLength` | `integer` | Number of steps |
| `impact` | `string` | Ultimate consequence if the full chain is exploited |
| `priorityRemediation` | `string` | The single fix that most effectively breaks this chain |

---

### `AttackChainNode`

A single node (step) in the attack graph.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique node ID (e.g., `"node-1"`) |
| `label` | `string` | Display label — impact nodes are prefixed with `⚠ IMPACT:` |
| `vulnerabilityName` | `string` | The vulnerability or impact that this node represents |
| `category` | [`VulnerabilityCategory`](#vulnerabilitycategory) | Classification for chain matching |
| `severity` | [`Severity`](#severity) | Severity of this step |
| `attackerAction` | `string` | What the attacker does at this step |
| `outcome` | `string` | What the attacker gains |
| `depth` | `integer` | Position in the chain (0 = entry point, higher = deeper) |

---

### `AttackChainEdge`

A directed edge connecting two nodes in the attack graph.

| Field | Type | Description |
|-------|------|-------------|
| `from` | `string` | Source node ID |
| `to` | `string` | Target node ID |
| `label` | `string` | Transition verb (e.g., `"enables"`, `"leads to"`, `"results in"`) |
| `description` | `string` | Detailed explanation of how one step leads to the next |
| `confidence` | `double` | Exploitability confidence (0.0–1.0) |

---

### `Severity`

Enumeration of vulnerability severity levels, ordered from most to least severe.

| Value | Description |
|-------|-------------|
| `CRITICAL` | Immediate exploitation risk, severe business impact |
| `HIGH` | Easily exploitable, significant data or access at risk |
| `MEDIUM` | Exploitable under certain conditions |
| `LOW` | Minor risk, limited impact |
| `INFO` | Informational finding, no direct exploitability |

---

### `GraphExportResponse`

Top-level response from the export-graph endpoint. All fields map directly to React Flow props.

| Field | Type | Description |
|-------|------|-------------|
| `targetUrl` | `string` | The scanned URL |
| `nodes` | `GraphExportNode[]` | React Flow nodes — pass to `<ReactFlow nodes={...} />` |
| `edges` | `GraphExportEdge[]` | React Flow edges — pass to `<ReactFlow edges={...} />` |
| `layout` | `GraphLayout` | Layout algorithm info and graph dimensions |
| `severityColorMap` | `map<string, string>` | Severity → hex color (for legends/badges) |
| `nodeTypeLegend` | `map<string, string>` | Node type → description |
| `stats` | `GraphStats` | Summary statistics for dashboard cards |
| `chainSummaries` | `ChainSummary[]` | Per-chain metadata with nodeIds/edgeIds for highlighting |

**`GraphExportNode`** fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique node ID |
| `type` | `string` | `"entry"`, `"vulnerability"`, or `"impact"` |
| `position` | `{ x, y }` | Pixel coordinates for layout |
| `data` | `object` | Payload: `label`, `severity`, `category`, `attackerAction`, `outcome`, `chainId`, `isImpact`, `isEntry`, etc. |
| `style` | `object` | CSS properties: `background`, `border`, `borderRadius`, `padding`, `fontSize`, etc. |
| `parentId` | `string` | Chain ID this node belongs to |

**`GraphExportEdge`** fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique edge ID |
| `source` | `string` | Source node ID |
| `target` | `string` | Target node ID |
| `sourceHandle` / `targetHandle` | `string` | Handle positions (`"right"`, `"left"`) |
| `type` | `string` | Edge type: `"smoothstep"` |
| `animated` | `boolean` | `true` for high-confidence edges (≥0.7) |
| `label` | `string` | e.g., `"enables (80%)"` |
| `markerEnd` | `{ type, color }` | Arrowhead configuration |
| `style` | `object` | CSS: `stroke`, `strokeWidth` |
| `labelStyle` | `object` | CSS: `fontSize`, `fontWeight`, `fill` |
| `data` | `object` | Extra: `description`, `confidence`, `confidenceLabel`, `chainId` |

**`GraphLayout`** fields:

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | `string` | `"dagre"` |
| `direction` | `string` | `"LR"` (left-to-right) |
| `nodeSpacingX` | `double` | Horizontal spacing (320px) |
| `nodeSpacingY` | `double` | Vertical spacing (200px) |
| `graphWidth` | `double` | Total graph width in pixels |
| `graphHeight` | `double` | Total graph height in pixels |

**`GraphStats`** fields:

| Field | Type | Description |
|-------|------|-------------|
| `totalNodes` | `int` | Total node count |
| `totalEdges` | `int` | Total edge count |
| `totalChains` | `int` | Number of attack chains |
| `maxRiskScore` | `double` | Highest chain risk score |
| `overallThreatLevel` | `string` | `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `topRemediation` | `string` | Single fix that breaks the most chains |
| `chainsBlockedByTopRemediation` | `int` | Chains neutralized by top fix |
| `nodesBySeverity` | `map<string, int>` | Node count per severity |
| `nodesByCategory` | `map<string, int>` | Node count per vuln category |

**`ChainSummary`** fields:

| Field | Type | Description |
|-------|------|-------------|
| `chainId` | `string` | e.g., `"chain-1"` |
| `title` | `string` | Chain title |
| `description` | `string` | Narrative description |
| `riskScore` | `double` | 0–100 |
| `maxSeverity` | `string` | Highest severity in chain |
| `chainLength` | `int` | Number of steps |
| `impact` | `string` | Ultimate consequence |
| `priorityRemediation` | `string` | Best fix for this chain |
| `nodeIds` | `string[]` | Node IDs in this chain — for highlight on hover |
| `edgeIds` | `string[]` | Edge IDs in this chain — for highlight on hover |

---

### `VulnerabilityCategory`

Classification used by the Attack Chain Engine to correlate vulnerabilities.

| Value | Display Name |
|-------|-------------|
| `MISSING_HEADER` | Missing Security Header |
| `CORS_MISCONFIGURATION` | CORS Misconfiguration |
| `XSS` | Cross-Site Scripting |
| `SQL_INJECTION` | SQL Injection |
| `OPEN_REDIRECT` | Open Redirect |
| `INFORMATION_DISCLOSURE` | Information Disclosure |
| `DANGEROUS_HTTP_METHOD` | Dangerous HTTP Method |
| `SSL_TLS_WEAKNESS` | SSL/TLS Weakness |
| `AUTHENTICATION_BYPASS` | Authentication Bypass |
| `SESSION_HIJACKING` | Session Hijacking |
| `DATA_EXFILTRATION` | Data Exfiltration |
| `PRIVILEGE_ESCALATION` | Privilege Escalation |
| `REMOTE_CODE_EXECUTION` | Remote Code Execution |
| `OTHER` | Other |

---

## Security Scanners

SentinelAPI runs **8 parallel security scanners** against the target:

| # | Scanner | What It Tests | Severity Range |
|---|---------|---------------|----------------|
| 1 | **Security Header Scanner** | Missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy` | HIGH – LOW |
| 2 | **HTTP Method Scanner** | Dangerous methods allowed (`TRACE`, `DELETE`, `PUT`); checks OPTIONS Allow header | MEDIUM – LOW |
| 3 | **SQL Injection Scanner** | Appends SQL payloads to query params, checks for DB error signatures (`SQL syntax`, `ORA-`, `mysql_`, `SQLSTATE`, etc.) | CRITICAL |
| 4 | **XSS Scanner** | Injects `<script>`, `<img onerror>`, `<svg onload>` payloads via query params, checks if reflected unencoded | HIGH |
| 5 | **Open Redirect Scanner** | Tests 15 common redirect params (`redirect`, `url`, `next`, `dest`, etc.) with an evil domain, checks for 3xx to attacker | MEDIUM |
| 6 | **CORS Scanner** | Sends `Origin: https://evil.com`, checks if `Access-Control-Allow-Origin` reflects it or is `*`, and checks `Allow-Credentials` | HIGH – MEDIUM |
| 7 | **Information Disclosure Scanner** | Checks `Server`, `X-Powered-By` headers for version leaks; triggers error pages to detect stack traces | MEDIUM – LOW |
| 8 | **SSL/TLS Scanner** | Inspects protocol version (flags TLS 1.0/1.1), cipher strength, certificate validity/expiry/hostname match | CRITICAL – INFO |

---

## Attack Chain Detection Rules

The **Attack Chain Visualization Engine** analyzes scan results and identifies **15 types of multi-step attack chains**:

#### High-Severity Combination Chains

| # | Chain Pattern | Trigger Condition | Max Risk |
|---|--------------|-------------------|----------|
| 1 | **CORS + XSS → Session Hijacking → Data Theft** | CORS misconfig + XSS both found | CRITICAL |
| 2 | **Info Disclosure → SQLi → Database Dump** | Info disclosure + SQL injection found | CRITICAL |
| 3 | **SQLi → Data Breach** *(standalone)* | SQL injection found (without info disclosure) | CRITICAL |
| 4 | **Missing X-Frame-Options + XSS → Clickjacking** | Missing X-Frame-Options header + XSS | CRITICAL |
| 5 | **Missing CSP + XSS → Account Takeover** | Missing CSP header + XSS | CRITICAL |
| 6 | **Open Redirect → Phishing → Credential Theft** | Open redirect found (± XSS variant) | CRITICAL |
| 7 | **SSL/TLS Weakness → MitM (± HSTS ± CORS)** | SSL/TLS issue found (optionally chained with missing HSTS and/or CORS) | CRITICAL |
| 8 | **XSS → Session Theft → Account Takeover** | XSS found (standalone, no CORS) | CRITICAL |
| 9 | **SQLi → File Write → Remote Code Execution** | SQL injection found | CRITICAL |

#### Standalone / Low-Barrier Chains

These fire even when only low/medium severity findings are present (e.g., scanning a well-configured public API):

| # | Chain Pattern | Trigger Condition | Max Risk |
|---|--------------|-------------------|----------|
| 10 | **Missing Security Headers → Weakened Defenses → Client-Side Attacks** | 2+ security headers missing | CRITICAL |
| 11 | **Information Disclosure → CVE Research → Targeted Exploit** | Info disclosure found (without SQLi) | CRITICAL |
| 12 | **TRACE Method → Cross-Site Tracing → Session Theft** | TRACE HTTP method enabled | CRITICAL |
| 13 | **PUT/DELETE Methods → Unauthorized Data Tampering** | PUT or DELETE methods not restricted | CRITICAL |
| 14 | **CORS Misconfiguration → Cross-Origin API Abuse → Data Theft** | CORS misconfig found (without XSS) | CRITICAL |
| 15 | **Reconnaissance → Defense Mapping → Attack Surface Exposure** | Missing headers + at least one of: info disclosure, dangerous methods, or SSL weakness | CRITICAL |

#### Meta Chain

| # | Chain Pattern | Trigger Condition | Max Risk |
|---|--------------|-------------------|----------|
| 16 | **Full Kill Chain: Recon → Exploit → Escalate → Compromise** | 2+ active vulnerability categories present (excluding missing headers) | CRITICAL |

### Risk Score Formula

```
riskScore = severityScore × avgConfidence × lengthFactor × 10

Where:
  severityScore = max node severity (CRITICAL=10, HIGH=8, MEDIUM=5, LOW=3, INFO=1)
  avgConfidence = average edge confidence (0.0 – 1.0)
  lengthFactor  = max(0.5, 1.0 - (chainLength - 2) × 0.1)
```

Shorter chains score higher (easier to exploit). Score range: **0 – 100**.

### Threat Level Thresholds

| Threat Level | Condition |
|-------------|-----------|
| `CRITICAL` | maxRisk ≥ 80 **or** 5+ chains |
| `HIGH` | maxRisk ≥ 60 **or** 3+ chains |
| `MEDIUM` | maxRisk ≥ 40 **or** 2+ chains |
| `LOW` | maxRisk ≥ 20 |
| `INFORMATIONAL` | chains > 0 but low risk |
| `NONE` | 0 chains found |

---

## Error Handling

### Validation Error `400 Bad Request`

Returned when the request body fails validation.

```json
{
  "timestamp": "2026-02-19T14:30:00.000",
  "status": 400,
  "error": "Validation Failed",
  "message": "targetUrl: Target URL must not be blank"
}
```

Common validation errors:

| Input | Error Message |
|-------|--------------|
| Missing `targetUrl` | `targetUrl: Target URL must not be blank` |
| `targetUrl: "ftp://..."` | `targetUrl: Target URL must start with http:// or https://` |
| Empty string | `targetUrl: Target URL must not be blank` |

### Server Error `500 Internal Server Error`

Returned when an unexpected error occurs during scanning.

```json
{
  "timestamp": "2026-02-19T14:30:00.000",
  "status": 500,
  "error": "Scan Failed",
  "message": "An unexpected error occurred during the scan: <details>"
}
```

---

## Architecture Overview

```
POST /api/scan
     │
     ▼
┌─────────────────┐
│  ScanController  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────────────────┐
│   ScanService    │────▶│  8 Security Scanners (parallel)│
└────────┬────────┘     └──────────────────────────────┘
         │                        │
         │                        ▼
         │              ┌──────────────────┐
         │              │  Vulnerabilities  │
         │              └────────┬─────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────┐
│     Attack Chain Visualization       │
│              Engine                  │
│                                     │
│  1. Classify vulns by category      │
│  2. Match against 16 chain rules    │
│  3. Build graph (nodes + edges)     │
│  4. Score risk & compute threat     │
│  5. Identify top remediation        │
└─────────────────┬───────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │  JSON Response  │
         └────────────────┘
```

---

## Quick Start

```bash
# Build
./mvnw clean package -DskipTests

# Run
java -jar target/SentinelAPI-0.0.1-SNAPSHOT.jar

# Scan a target
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com"}'

# Get only attack chains
curl -X POST http://localhost:8080/api/scan/attack-chains \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com"}'

# Export React Flow-compatible graph
curl -X POST http://localhost:8080/api/scan/export-graph \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://example.com"}'
```

