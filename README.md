<p align="center">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/Spring%20Boot-3.5-6DB33F?style=for-the-badge&logo=springboot&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" />
</p>

<h1 align="center">🛡️ SentinelAPI</h1>

<p align="center">
  <b>Automated API Security Scanner & Attack Chain Visualization Engine</b><br/>
  <i>Point it at any API endpoint — get a full vulnerability report with multi-step attack chain analysis, ready to visualize in React Flow.</i>
</p>

---

## 🚀 What is SentinelAPI?

SentinelAPI is a backend security intelligence tool built with **Spring Boot 3.5** and **Java 21**. It takes any HTTP(S) API endpoint and:

1. **Scans** it in parallel using 8 specialized security scanners
2. **Detects** common vulnerabilities (SQL injection, XSS, CORS misconfig, missing headers, etc.)
3. **Analyzes** how discovered weaknesses chain together into realistic multi-step exploits
4. **Generates** a structured vulnerability report with an **Attack Chain Visualization** graph
5. **Exports** React Flow-compatible JSON for interactive frontend rendering

> Think of it as an automated penetration tester that doesn't just find bugs — it shows you how an attacker would **chain them together** to maximize damage.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **8 Parallel Security Scanners** | Security headers, SQL injection, XSS, CORS, open redirects, SSL/TLS, HTTP methods, info disclosure |
| 🔗 **Attack Chain Engine** | 16 chain detection rules that model real-world multi-step attack scenarios |
| 📊 **Risk Scoring** | Composite risk scores (0–100) based on severity, exploit confidence, and chain length |
| 🎯 **Smart Remediation** | Identifies the single fix that breaks the most attack chains |
| ⚡ **React Flow Export** | Pre-positioned nodes, styled edges, color maps, and chain summaries — plug directly into `<ReactFlow />` |
| 🧵 **Virtual Threads** | Java 21 virtual threads for high-concurrency scanning |
| 📋 **Structured Reports** | JSON responses with severity summaries, individual findings, and full attack graph data |

---

## 🏗️ Architecture

```
POST /api/scan
     │
     ▼
┌─────────────────┐
│  ScanController  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   ScanService    │────▶│  8 Security Scanners (parallel)   │
└────────┬────────┘     └──────────────────────────────────┘
         │                          │
         │                          ▼
         │                ┌──────────────────┐
         │                │  Vulnerabilities  │
         │                └────────┬─────────┘
         │                         │
         ▼                         ▼
┌──────────────────────────────────────────┐
│   Attack Chain Visualization Engine       │
│                                          │
│  1. Classify vulns by category           │
│  2. Match against 16 chain rules         │
│  3. Build directed graph (nodes + edges) │
│  4. Score risk & compute threat level    │
│  5. Identify top remediation             │
└────────────────┬─────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────┐
│       GraphExportService (optional)       │
│                                          │
│  Transforms to React Flow format:        │
│  - Positioned nodes with severity styles │
│  - Animated edges with confidence labels │
│  - Layout metadata & color maps          │
│  - Per-chain summaries for highlighting  │
└────────────────┬─────────────────────────┘
                 │
                 ▼
          ┌──────────────┐
          │ JSON Response │
          └──────────────┘
```

---

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Java 21 |
| Framework | Spring Boot 3.5 |
| HTTP Client | Spring WebFlux (WebClient) |
| Validation | Jakarta Bean Validation |
| Build | Maven |
| Code Gen | Lombok |

---

## ⚡ Quick Start

### Prerequisites

- **Java 21+** installed
- **Maven 3.9+** (or use the included Maven wrapper)

### 1. Clone

```bash
git clone https://github.com/your-username/SentinelAPI.git
cd SentinelAPI
```

### 2. Build

```bash
./mvnw clean package -DskipTests
```

### 3. Run

```bash
java -jar target/SentinelAPI-0.0.1-SNAPSHOT.jar
```

The server starts on **http://localhost:8080**.

### 4. Scan a Target

```bash
# Full security scan + attack chains
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://jsonplaceholder.typicode.com"}'

# Attack chains only
curl -X POST http://localhost:8080/api/scan/attack-chains \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://jsonplaceholder.typicode.com"}'

# React Flow graph export
curl -X POST http://localhost:8080/api/scan/export-graph \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://jsonplaceholder.typicode.com"}'
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Full scan — vulnerabilities + attack chain visualization |
| `POST` | `/api/scan/attack-chains` | Scan and return only the attack chain graph data |
| `POST` | `/api/scan/export-graph` | Scan and return React Flow-compatible graph JSON |

### Request Body (all POST endpoints)

```json
{
  "targetUrl": "https://example.com"
}
```

> 📖 **Full API documentation with request/response examples, data models, and React integration guides → [`API_DOCS.md`](API_DOCS.md)**

---

## 🔍 Security Scanners

SentinelAPI runs **8 scanners in parallel** against the target:

| # | Scanner | Tests For | Severity |
|---|---------|-----------|----------|
| 1 | **Security Header Scanner** | Missing `Strict-Transport-Security`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy` | HIGH – LOW |
| 2 | **HTTP Method Scanner** | Dangerous methods (`TRACE`, `DELETE`, `PUT`) via OPTIONS | MEDIUM – LOW |
| 3 | **SQL Injection Scanner** | SQL payloads in query params, DB error signatures | CRITICAL |
| 4 | **XSS Scanner** | Reflected `<script>`, `<img onerror>`, `<svg onload>` payloads | HIGH |
| 5 | **Open Redirect Scanner** | 15 common redirect parameters with evil domain | MEDIUM |
| 6 | **CORS Scanner** | `Access-Control-Allow-Origin` reflection, wildcard `*`, credentials | HIGH – MEDIUM |
| 7 | **Info Disclosure Scanner** | `Server` / `X-Powered-By` version leaks, error stack traces | MEDIUM – LOW |
| 8 | **SSL/TLS Scanner** | Protocol version, cipher strength, cert validity/expiry | CRITICAL – INFO |

---

## 🔗 Attack Chain Engine

The engine analyzes discovered vulnerabilities and identifies **16 types of multi-step attack chains** — showing how individual weaknesses combine into realistic exploit scenarios.

### Example Chains

| Chain | Trigger | Impact |
|-------|---------|--------|
| **CORS + XSS → Session Hijacking → Data Theft** | CORS misconfig + XSS | Full account takeover |
| **Info Disclosure → SQLi → Database Dump** | Version leak + SQL injection | Complete DB compromise |
| **Missing Headers → Defense Degradation → Client-Side Attacks** | 2+ missing headers | XSS, clickjacking, SSL stripping |
| **SSL Weakness → MitM → Data Interception** | Weak TLS + missing HSTS | Traffic interception |
| **Full Kill Chain: Recon → Exploit → Escalate → Compromise** | 2+ vuln categories | Total system compromise |

### Risk Score Formula

```
riskScore = severityScore × avgConfidence × lengthFactor × 10

  severityScore  → CRITICAL=10, HIGH=8, MEDIUM=5, LOW=3, INFO=1
  avgConfidence  → average edge confidence (0.0–1.0)
  lengthFactor   → max(0.5, 1.0 - (chainLength - 2) × 0.1)
```

Shorter chains = higher scores (easier to exploit). Range: **0–100**.

### Threat Levels

| Level | Condition |
|-------|-----------|
| `CRITICAL` | Risk ≥ 80 or 5+ chains |
| `HIGH` | Risk ≥ 60 or 3+ chains |
| `MEDIUM` | Risk ≥ 40 or 2+ chains |
| `LOW` | Risk ≥ 20 |
| `INFORMATIONAL` | Chains found but low risk |
| `NONE` | No chains detected |

---

## 🎨 React Flow Integration

The `/api/scan/export-graph` endpoint returns data **ready to plug into React Flow** with zero transformation:

```jsx
import ReactFlow from 'reactflow';

const res = await fetch('/api/scan/export-graph', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ targetUrl: 'https://example.com' })
});

const { nodes, edges, layout, stats, chainSummaries, severityColorMap } = await res.json();

// Drop directly into ReactFlow — nodes are pre-positioned & styled
<ReactFlow
  nodes={nodes}
  edges={edges}
  fitView
  defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
/>
```

### Chain Highlighting on Hover

Each `chainSummary` includes `nodeIds[]` and `edgeIds[]` for interactive chain highlighting:

```jsx
const [activeChain, setActiveChain] = useState(null);

const styledNodes = nodes.map(n => ({
  ...n,
  style: {
    ...n.style,
    opacity: !activeChain || activeChain.nodeIds.includes(n.id) ? 1 : 0.2
  }
}));
```

---

## 📁 Project Structure

```
SentinelAPI/
├── src/main/java/com/sentinelapi/
│   ├── SentinelApiApplication.java       # Entry point
│   ├── config/
│   │   └── WebClientConfig.java          # WebClient bean configuration
│   ├── controller/
│   │   └── ScanController.java           # REST endpoints
│   ├── dto/
│   │   ├── ScanRequest.java              # Input validation
│   │   ├── Vulnerability.java            # Single finding
│   │   ├── VulnerabilityReport.java      # Full scan response
│   │   ├── AttackChain.java              # One attack path
│   │   ├── AttackChainNode.java          # Graph node
│   │   ├── AttackChainEdge.java          # Graph edge
│   │   ├── AttackChainVisualization.java # All chains + metadata
│   │   └── graph/
│   │       ├── GraphExportNode.java      # React Flow node
│   │       ├── GraphExportEdge.java      # React Flow edge
│   │       └── GraphExportResponse.java  # Full export response
│   ├── engine/
│   │   └── AttackChainEngine.java        # 16 chain detection rules
│   ├── exception/
│   │   └── GlobalExceptionHandler.java   # Error responses
│   ├── model/
│   │   ├── Severity.java                 # CRITICAL → INFO
│   │   └── VulnerabilityCategory.java    # 14 vuln categories
│   ├── scanner/
│   │   ├── SecurityScanner.java          # Scanner interface
│   │   └── impl/
│   │       ├── CorsScanner.java
│   │       ├── HttpMethodScanner.java
│   │       ├── InformationDisclosureScanner.java
│   │       ├── OpenRedirectScanner.java
│   │       ├── SecurityHeaderScanner.java
│   │       ├── SqlInjectionScanner.java
│   │       ├── SslTlsScanner.java
│   │       └── XssScanner.java
│   └── service/
│       ├── ScanService.java              # Orchestrates scanners + engine
│       └── GraphExportService.java       # React Flow transformation
├── src/main/resources/
│   └── application.properties
├── API_DOCS.md                           # Full API documentation
├── pom.xml
└── mvnw / mvnw.cmd                      # Maven wrapper
```

---

## ⚙️ Configuration

Configuration is in `src/main/resources/application.properties`:

| Property | Default | Description |
|----------|---------|-------------|
| `server.port` | `8080` | Server port |
| `spring.threads.virtual.enabled` | `true` | Java 21 virtual threads |
| `logging.level.com.sentinelapi` | `INFO` | Application log level |
| `logging.level.com.sentinelapi.scanner` | `DEBUG` | Scanner-level logging |

---

## 📋 Example Scan Output

```bash
curl -s -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://jsonplaceholder.typicode.com"}' | jq '.attackChainVisualization | {totalChains, maxRiskScore, overallThreatLevel, topRemediation}'
```

```json
{
  "totalChains": 3,
  "maxRiskScore": 56.0,
  "overallThreatLevel": "MEDIUM",
  "topRemediation": "Implement all missing security headers with recommended values"
}
```

---

## 🛣️ Roadmap

- [x] 8 parallel security scanners
- [x] Attack Chain Visualization Engine (16 chain rules)
- [x] React Flow graph export API
- [x] Risk scoring & threat levels
- [x] Smart remediation prioritization
- [ ] React frontend dashboard (coming soon)
- [ ] Authentication & rate limiting
- [ ] Scan history & persistence (PostgreSQL)
- [ ] PDF report generation
- [ ] Custom scanner plugin system
- [ ] CI/CD integration (GitHub Actions, Jenkins)
- [ ] WebSocket for real-time scan progress

---

## ⚠️ Disclaimer

SentinelAPI is designed for **authorized security testing only**. Always ensure you have explicit permission before scanning any API endpoint. Unauthorized scanning of systems you do not own or have permission to test is **illegal** and **unethical**.

The authors are not responsible for any misuse of this tool.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made with ☕ and Java 21
</p>

