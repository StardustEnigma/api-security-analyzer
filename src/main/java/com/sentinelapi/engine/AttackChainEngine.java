package com.sentinelapi.engine;

import com.sentinelapi.dto.*;
import com.sentinelapi.model.Severity;
import com.sentinelapi.model.VulnerabilityCategory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;


@Slf4j
@Component
public class AttackChainEngine {

    private final AtomicInteger nodeCounter = new AtomicInteger(0);
    private final AtomicInteger chainCounter = new AtomicInteger(0);


    public AttackChainVisualization analyze(String targetUrl, List<Vulnerability> vulnerabilities) {
        log.info("Attack Chain Engine: analyzing {} vulnerabilities for {}", vulnerabilities.size(), targetUrl);

        nodeCounter.set(0);
        chainCounter.set(0);

        // Classify each vulnerability
        Map<VulnerabilityCategory, List<Vulnerability>> classified = classifyVulnerabilities(vulnerabilities);

        // Build all possible attack chains
        List<AttackChain> chains = new ArrayList<>();

        // Multi-vuln combination chains
        chains.addAll(buildCorsXssSessionHijackChain(classified));
        chains.addAll(buildInfoDisclosureSqlInjectionChain(classified));
        chains.addAll(buildMissingHeadersXssClickjackChain(classified));
        chains.addAll(buildOpenRedirectPhishingChain(classified));
        chains.addAll(buildSslMitmChain(classified));
        chains.addAll(buildXssToAccountTakeoverChain(classified));
        chains.addAll(buildSqlInjectionToRceChain(classified));

        // Standalone / low-barrier chains (fire even without high-severity combos)
        chains.addAll(buildMissingHeadersDefenseDegradationChain(classified));
        chains.addAll(buildInfoDisclosureStandaloneChain(classified));
        chains.addAll(buildDangerousHttpMethodChain(classified));
        chains.addAll(buildCorsStandaloneChain(classified));
        chains.addAll(buildSecurityPostureDegradationChain(classified));

        // Full kill chain
        chains.addAll(buildFullKillChain(classified));

        // Deduplicate chains with identical node sets
        chains = deduplicateChains(chains);

        // Sort by risk score descending
        chains.sort(Comparator.comparingDouble(AttackChain::getRiskScore).reversed());

        // Build combined graph
        List<AttackChainNode> allNodes = new ArrayList<>();
        List<AttackChainEdge> allEdges = new ArrayList<>();
        for (AttackChain chain : chains) {
            allNodes.addAll(chain.getNodes());
            allEdges.addAll(chain.getEdges());
        }

        // Severity distribution
        Map<String, Integer> sevDist = new LinkedHashMap<>();
        for (AttackChain chain : chains) {
            String key = chain.getMaxSeverity().name();
            sevDist.merge(key, 1, Integer::sum);
        }

        // Find the top remediation that blocks the most chains
        Map<String, Long> remediationCounts = chains.stream()
                .map(AttackChain::getPriorityRemediation)
                .collect(Collectors.groupingBy(r -> r, Collectors.counting()));

        String topRemediation = remediationCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("No specific remediation identified");

        int chainsBlocked = remediationCounts.getOrDefault(topRemediation, 0L).intValue();

        double maxRisk = chains.stream()
                .mapToDouble(AttackChain::getRiskScore)
                .max()
                .orElse(0.0);

        String threatLevel = computeThreatLevel(maxRisk, chains.size());

        log.info("Attack Chain Engine: found {} chains, max risk={}, threat={}",
                chains.size(), maxRisk, threatLevel);

        return AttackChainVisualization.builder()
                .targetUrl(targetUrl)
                .attackChains(chains)
                .totalChains(chains.size())
                .maxRiskScore(Math.round(maxRisk * 10.0) / 10.0)
                .overallThreatLevel(threatLevel)
                .allNodes(allNodes)
                .allEdges(allEdges)
                .chainSeverityDistribution(sevDist)
                .topRemediation(topRemediation)
                .chainsBlockedByTopRemediation(chainsBlocked)
                .build();
    }

    // ===================== CHAIN BUILDERS =====================

    private List<AttackChain> buildCorsXssSessionHijackChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> cors = classified.getOrDefault(VulnerabilityCategory.CORS_MISCONFIGURATION, List.of());
        List<Vulnerability> xss = classified.getOrDefault(VulnerabilityCategory.XSS, List.of());

        if (!cors.isEmpty() && !xss.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(cors.getFirst(), 0,
                    "Exploit CORS misconfiguration",
                    "Cross-origin requests are accepted from attacker's domain");
            AttackChainNode n2 = createNode(xss.getFirst(), 1,
                    "Inject malicious script via XSS",
                    "JavaScript executes in victim's browser context");
            AttackChainNode n3 = createImpactNode(2, "Session Hijacking",
                    "Steal session tokens via injected script + CORS bypass",
                    "Attacker captures authenticated session cookies/tokens");
            AttackChainNode n4 = createImpactNode(3, "Data Exfiltration",
                    "Use stolen session to extract sensitive data",
                    "Full access to victim's account data");

            nodes.addAll(List.of(n1, n2, n3, n4));
            edges.add(createEdge(n1, n2, "enables", "CORS allows cross-origin script injection", 0.8));
            edges.add(createEdge(n2, n3, "leads to", "Injected script steals session tokens", 0.85));
            edges.add(createEdge(n3, n4, "results in", "Stolen session provides data access", 0.9));

            chains.add(buildChain("CORS + XSS → Session Hijacking → Data Theft",
                    "An attacker exploits CORS misconfiguration to make cross-origin requests, "
                            + "then leverages XSS to inject scripts that steal session tokens, "
                            + "ultimately exfiltrating sensitive user data.",
                    nodes, edges, "Full unauthorized access to user accounts and data",
                    "Fix CORS configuration to reject untrusted origins"));
        }

        return chains;
    }


    private List<AttackChain> buildInfoDisclosureSqlInjectionChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> info = classified.getOrDefault(VulnerabilityCategory.INFORMATION_DISCLOSURE, List.of());
        List<Vulnerability> sqli = classified.getOrDefault(VulnerabilityCategory.SQL_INJECTION, List.of());

        if (!info.isEmpty() && !sqli.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(info.getFirst(), 0,
                    "Gather technology stack information from disclosed headers/errors",
                    "Attacker identifies database type, framework, and version");
            AttackChainNode n2 = createNode(sqli.getFirst(), 1,
                    "Craft targeted SQL injection payloads based on identified DB",
                    "Direct database query manipulation achieved");
            AttackChainNode n3 = createImpactNode(2, "Database Dump",
                    "Extract entire database contents via UNION-based or blind SQLi",
                    "Complete database exfiltration including credentials");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "informs", "Stack info helps craft precise SQLi payloads", 0.7));
            edges.add(createEdge(n2, n3, "enables", "SQL injection allows arbitrary DB queries", 0.95));

            chains.add(buildChain("Info Disclosure → SQLi → Database Dump",
                    "Leaked server information reveals the technology stack, enabling the attacker "
                            + "to craft targeted SQL injection payloads that dump the entire database.",
                    nodes, edges, "Complete database compromise including user credentials and sensitive records",
                    "Use parameterized queries and suppress server version headers"));
        }

        // Standalone SQL injection chain (even without info disclosure)
        if (info.isEmpty() && !sqli.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(sqli.getFirst(), 0,
                    "Exploit SQL injection vulnerability",
                    "Attacker can execute arbitrary SQL commands");
            AttackChainNode n2 = createImpactNode(1, "Data Breach",
                    "Dump user tables, credentials, and sensitive records",
                    "Massive data breach");

            nodes.addAll(List.of(n1, n2));
            edges.add(createEdge(n1, n2, "leads to", "SQL injection directly enables data extraction", 0.95));

            chains.add(buildChain("SQL Injection → Data Breach",
                    "SQL injection vulnerability allows direct database manipulation and data exfiltration.",
                    nodes, edges, "Database compromise and data breach",
                    "Implement parameterized queries / prepared statements immediately"));
        }

        return chains;
    }

    private List<AttackChain> buildMissingHeadersXssClickjackChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> headers = classified.getOrDefault(VulnerabilityCategory.MISSING_HEADER, List.of());
        List<Vulnerability> xss = classified.getOrDefault(VulnerabilityCategory.XSS, List.of());

        boolean missingFrameOptions = headers.stream()
                .anyMatch(v -> v.getName().contains("X-Frame-Options"));
        boolean missingCSP = headers.stream()
                .anyMatch(v -> v.getName().contains("Content-Security-Policy"));

        if (missingFrameOptions && !xss.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.MEDIUM, 0,
                    "Missing X-Frame-Options",
                    "Embed target site in a hidden iframe on attacker's page",
                    "Target page rendered inside attacker-controlled frame");
            AttackChainNode n2 = createNode(xss.getFirst(), 1,
                    "Inject script payload via XSS within the framed page",
                    "Script executes in the context of the framed origin");
            AttackChainNode n3 = createImpactNode(2, "Clickjacking + Credential Theft",
                    "Trick user into clicking invisible buttons, steal form inputs and sessions",
                    "User unknowingly performs actions and leaks credentials");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "enables", "Iframe embedding allows XSS delivery", 0.7));
            edges.add(createEdge(n2, n3, "leads to", "Script captures keystrokes and session data", 0.8));

            chains.add(buildChain("Clickjacking + XSS → Credential Theft",
                    "Missing X-Frame-Options allows the page to be embedded in an iframe. "
                            + "Combined with XSS, an attacker can perform clickjacking attacks and steal credentials.",
                    nodes, edges, "User credential theft via clickjacking and script injection",
                    "Add X-Frame-Options: DENY and Content-Security-Policy headers"));
        }

        if (missingCSP && !xss.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.MEDIUM, 0,
                    "Missing Content-Security-Policy",
                    "No CSP means no inline script restrictions",
                    "Browser allows execution of any inline scripts");
            AttackChainNode n2 = createNode(xss.getFirst(), 1,
                    "Inject and execute arbitrary inline JavaScript",
                    "Full script execution without CSP blocking");
            AttackChainNode n3 = createImpactNode(2, "Account Takeover",
                    "Exfiltrate tokens, modify DOM, redirect user",
                    "Complete control over user's session");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "permits", "Missing CSP allows inline script execution", 0.85));
            edges.add(createEdge(n2, n3, "achieves", "Unrestricted scripts enable account takeover", 0.8));

            chains.add(buildChain("Missing CSP + XSS → Account Takeover",
                    "Without Content-Security-Policy, the browser cannot block injected scripts. "
                            + "XSS payloads execute freely, enabling full account takeover.",
                    nodes, edges, "Account takeover through unrestricted script execution",
                    "Implement a strict Content-Security-Policy header"));
        }

        return chains;
    }

    private List<AttackChain> buildOpenRedirectPhishingChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> redirects = classified.getOrDefault(VulnerabilityCategory.OPEN_REDIRECT, List.of());
        List<Vulnerability> xss = classified.getOrDefault(VulnerabilityCategory.XSS, List.of());

        if (!redirects.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(redirects.getFirst(), 0,
                    "Craft a legitimate-looking URL that redirects to attacker's site",
                    "Victim trusts the link because domain is legitimate");
            AttackChainNode n2 = createImpactNode(1, "Phishing Page",
                    "Redirect lands on a cloned login page controlled by attacker",
                    "Victim enters credentials on fake login page");
            AttackChainNode n3 = createImpactNode(2, "Credential Theft",
                    "Captured credentials used to access victim's real account",
                    "Account compromise via phished credentials");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "redirects to", "User lands on attacker-controlled phishing page", 0.75));
            edges.add(createEdge(n2, n3, "captures", "Fake login form steals real credentials", 0.8));

            chains.add(buildChain("Open Redirect → Phishing → Credential Theft",
                    "An open redirect vulnerability allows attackers to craft legitimate-looking URLs "
                            + "that redirect users to phishing pages, stealing their credentials.",
                    nodes, edges, "Credential theft via trusted-domain phishing",
                    "Validate redirect targets against an allowlist of trusted domains"));

            // If XSS is also present, build a combined chain
            if (!xss.isEmpty()) {
                List<AttackChainNode> nodes2 = new ArrayList<>();
                List<AttackChainEdge> edges2 = new ArrayList<>();

                AttackChainNode r1 = createNode(redirects.getFirst(), 0,
                        "Use open redirect to deliver XSS payload via URL",
                        "Victim clicks trusted-looking link");
                AttackChainNode r2 = createNode(xss.getFirst(), 1,
                        "XSS payload executes after redirect bounce",
                        "Script runs in the context of the target origin");
                AttackChainNode r3 = createImpactNode(2, "Token Exfiltration",
                        "Injected script sends session tokens to attacker's server",
                        "Attacker gains authenticated session access");

                nodes2.addAll(List.of(r1, r2, r3));
                edges2.add(createEdge(r1, r2, "delivers", "Redirect URL carries XSS payload", 0.7));
                edges2.add(createEdge(r2, r3, "steals", "Script exfiltrates authentication tokens", 0.85));

                chains.add(buildChain("Open Redirect + XSS → Token Theft",
                        "Open redirect delivers an XSS payload via a trusted URL, "
                                + "allowing script execution and session token exfiltration.",
                        nodes2, edges2, "Session hijacking via redirect-delivered XSS",
                        "Fix open redirect and implement Content-Security-Policy"));
            }
        }

        return chains;
    }

    private List<AttackChain> buildSslMitmChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> ssl = classified.getOrDefault(VulnerabilityCategory.SSL_TLS_WEAKNESS, List.of());
        List<Vulnerability> cors = classified.getOrDefault(VulnerabilityCategory.CORS_MISCONFIGURATION, List.of());
        List<Vulnerability> headers = classified.getOrDefault(VulnerabilityCategory.MISSING_HEADER, List.of());

        boolean missingHSTS = headers.stream()
                .anyMatch(v -> v.getName().contains("Strict-Transport-Security"));

        if (!ssl.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(ssl.getFirst(), 0,
                    "Exploit weak SSL/TLS configuration",
                    "Attacker can intercept or downgrade encrypted connections");

            if (missingHSTS) {
                AttackChainNode n1b = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.HIGH, 1,
                        "Missing HSTS",
                        "Without HSTS, browsers don't enforce HTTPS",
                        "SSL stripping attack becomes possible");
                AttackChainNode n2 = createImpactNode(2, "Man-in-the-Middle",
                        "Intercept and modify traffic between user and server",
                        "Full visibility into transmitted data");

                nodes.addAll(List.of(n1, n1b, n2));
                edges.add(createEdge(n1, n1b, "combined with", "Weak TLS + missing HSTS enables SSL stripping", 0.7));
                edges.add(createEdge(n1b, n2, "enables", "Downgraded connection allows traffic interception", 0.8));
            } else {
                AttackChainNode n2 = createImpactNode(1, "Man-in-the-Middle",
                        "Exploit weak protocol/cipher to intercept encrypted traffic",
                        "Partial or full traffic decryption");
                nodes.addAll(List.of(n1, n2));
                edges.add(createEdge(n1, n2, "enables", "Weak TLS allows traffic interception", 0.6));
            }

            if (!cors.isEmpty()) {
                AttackChainNode n3 = createNode(cors.getFirst(), nodes.size(),
                        "Leverage CORS misconfiguration from MitM position",
                        "Inject cross-origin requests via intercepted responses");
                AttackChainNode n4 = createImpactNode(nodes.size() + 1, "Data Exfiltration",
                        "Extract sensitive data through manipulated cross-origin requests",
                        "Complete data compromise");
                edges.add(createEdge(nodes.getLast(), n3, "amplified by", "MitM + CORS enables broader attack", 0.65));
                edges.add(createEdge(n3, n4, "results in", "Cross-origin data extraction", 0.75));
                nodes.addAll(List.of(n3, n4));
            }

            chains.add(buildChain("SSL/TLS Weakness → MitM" + (cors.isEmpty() ? "" : " → Data Exfiltration"),
                    "Weak SSL/TLS configuration allows an attacker to perform man-in-the-middle attacks"
                            + (missingHSTS ? ", amplified by missing HSTS enabling SSL stripping" : "")
                            + (cors.isEmpty() ? "." : ", further escalated via CORS misconfiguration to exfiltrate data."),
                    nodes, edges,
                    "Traffic interception and" + (cors.isEmpty() ? " potential data exposure" : " full data exfiltration"),
                    "Upgrade to TLS 1.2+ with strong cipher suites and add HSTS header"));
        }

        return chains;
    }


    private List<AttackChain> buildXssToAccountTakeoverChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> xss = classified.getOrDefault(VulnerabilityCategory.XSS, List.of());
        List<Vulnerability> cors = classified.getOrDefault(VulnerabilityCategory.CORS_MISCONFIGURATION, List.of());

        // Only build standalone XSS chain if CORS isn't present (otherwise covered by combined chain)
        if (!xss.isEmpty() && cors.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(xss.getFirst(), 0,
                    "Deliver XSS payload to victim (e.g., via crafted link)",
                    "Malicious script executes in victim's browser");
            AttackChainNode n2 = createImpactNode(1, "Session Token Theft",
                    "Script reads cookies, localStorage, or session storage",
                    "Attacker obtains valid session tokens");
            AttackChainNode n3 = createImpactNode(2, "Account Takeover",
                    "Replay stolen tokens to impersonate the victim",
                    "Full control of victim's account");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "steals", "Injected script captures authentication tokens", 0.85));
            edges.add(createEdge(n2, n3, "enables", "Stolen tokens allow account impersonation", 0.9));

            chains.add(buildChain("XSS → Session Theft → Account Takeover",
                    "Cross-site scripting allows an attacker to steal session tokens "
                            + "and take over user accounts.",
                    nodes, edges, "Complete account takeover",
                    "Sanitize all user inputs and implement Content-Security-Policy"));
        }

        return chains;
    }

    /**
     * Chain: SQL Injection → Remote Code Execution (via stacked queries / file write)
     */
    private List<AttackChain> buildSqlInjectionToRceChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> sqli = classified.getOrDefault(VulnerabilityCategory.SQL_INJECTION, List.of());

        if (!sqli.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(sqli.getFirst(), 0,
                    "Exploit SQL injection to execute stacked queries",
                    "Attacker gains arbitrary SQL execution");
            AttackChainNode n2 = createImpactNode(1, "File System Access",
                    "Use SQL features (INTO OUTFILE, xp_cmdshell, COPY TO) to write files",
                    "Attacker can write arbitrary files to the server");
            AttackChainNode n3 = createImpactNode(2, "Remote Code Execution",
                    "Write a web shell or execute OS commands via database features",
                    "Full server compromise");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "escalates to", "SQL features allow file system access", 0.5));
            edges.add(createEdge(n2, n3, "achieves", "File write enables code execution", 0.4));

            chains.add(buildChain("SQL Injection → File Write → Remote Code Execution",
                    "SQL injection can potentially be escalated to remote code execution "
                            + "via database file-write features or OS command execution functions.",
                    nodes, edges, "Full server compromise via remote code execution",
                    "Use parameterized queries and restrict database user privileges"));
        }

        return chains;
    }

    /**
     * Chain: Multiple missing security headers → Defense Degradation → Exploitable Attack Surface
     * Fires when 2+ security headers are missing, even with no other vuln types.
     */
    private List<AttackChain> buildMissingHeadersDefenseDegradationChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> headers = classified.getOrDefault(VulnerabilityCategory.MISSING_HEADER, List.of());

        if (headers.size() >= 2) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            boolean missingCSP = headers.stream().anyMatch(v -> v.getName().contains("Content-Security-Policy"));
            boolean missingFrameOpts = headers.stream().anyMatch(v -> v.getName().contains("X-Frame-Options"));
            boolean missingHSTS = headers.stream().anyMatch(v -> v.getName().contains("Strict-Transport-Security"));
            boolean missingXCTO = headers.stream().anyMatch(v -> v.getName().contains("X-Content-Type-Options"));

            AttackChainNode n1 = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.MEDIUM, 0,
                    "Missing Security Headers (" + headers.size() + " headers)",
                    "Identify " + headers.size() + " missing security headers via response analysis",
                    "Application lacks browser-side security controls");
            nodes.add(n1);

            if (missingCSP) {
                AttackChainNode n = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.MEDIUM, 1,
                        "No Content-Security-Policy",
                        "Without CSP, browser allows execution of any injected inline scripts and loading of external resources",
                        "XSS attacks are not mitigated by the browser");
                edges.add(createEdge(nodes.getLast(), n, "exposes", "Missing CSP removes script execution restrictions", 0.8));
                nodes.add(n);
            }

            if (missingFrameOpts) {
                AttackChainNode n = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.MEDIUM, nodes.size(),
                        "No X-Frame-Options",
                        "Embed application in hidden iframe to perform clickjacking",
                        "Users can be tricked into clicking hidden UI elements");
                edges.add(createEdge(nodes.getLast(), n, "combined with", "Clickjacking becomes possible without frame protection", 0.75));
                nodes.add(n);
            }

            if (missingHSTS && !missingCSP && !missingFrameOpts) {
                AttackChainNode n = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.HIGH, nodes.size(),
                        "No Strict-Transport-Security",
                        "Perform SSL stripping to downgrade connections to HTTP",
                        "Traffic can be intercepted in plaintext");
                edges.add(createEdge(nodes.getLast(), n, "amplifies", "Missing HSTS allows protocol downgrade", 0.7));
                nodes.add(n);
            }

            // Impact node
            List<String> impacts = new ArrayList<>();
            if (missingCSP) impacts.add("script injection");
            if (missingFrameOpts) impacts.add("clickjacking");
            if (missingHSTS) impacts.add("SSL stripping");
            if (missingXCTO) impacts.add("MIME-sniffing attacks");
            String impactSummary = impacts.isEmpty() ? "weakened browser-side defenses" : String.join(", ", impacts);

            AttackChainNode impact = createImpactNode(nodes.size(), "Weakened Security Posture",
                    "Exploit the absence of browser security controls to perform " + impactSummary,
                    "Application is vulnerable to client-side attacks that headers would have prevented");
            edges.add(createEdge(nodes.getLast(), impact, "results in", "Missing defenses create exploitable attack surface", 0.7));
            nodes.add(impact);

            chains.add(buildChain("Missing Security Headers → Weakened Defenses → Client-Side Attacks",
                    headers.size() + " security headers are missing, progressively degrading the application's "
                            + "browser-side security controls. This creates an attack surface for "
                            + impactSummary + ".",
                    nodes, edges,
                    "Client-side attacks enabled: " + impactSummary,
                    "Implement all missing security headers, prioritizing Content-Security-Policy and Strict-Transport-Security"));
        }

        return chains;
    }

    /**
     * Chain: Information Disclosure (standalone) → Targeted Reconnaissance → Precision Exploit
     */
    private List<AttackChain> buildInfoDisclosureStandaloneChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> info = classified.getOrDefault(VulnerabilityCategory.INFORMATION_DISCLOSURE, List.of());
        List<Vulnerability> sqli = classified.getOrDefault(VulnerabilityCategory.SQL_INJECTION, List.of());

        // Only standalone — skip if SQLi is present (handled by the combo chain)
        if (!info.isEmpty() && sqli.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(info.getFirst(), 0,
                    "Extract server technology fingerprint from response headers and error pages",
                    "Server version, framework, and technology stack identified");

            AttackChainNode n2 = createCategoryNode(VulnerabilityCategory.INFORMATION_DISCLOSURE, Severity.MEDIUM, 1,
                    "CVE Lookup & Exploit Research",
                    "Search public CVE databases for known vulnerabilities matching the disclosed versions",
                    "Attacker finds known exploits for the exact software version");

            AttackChainNode n3 = createImpactNode(2, "Targeted Exploitation",
                    "Deploy version-specific exploits against identified software",
                    "Server compromise via known vulnerability exploit");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "informs", "Disclosed versions guide CVE research", 0.75));
            edges.add(createEdge(n2, n3, "enables", "Known CVEs provide ready-made exploit paths", 0.5));

            chains.add(buildChain("Information Disclosure → CVE Research → Targeted Exploit",
                    "Server version and technology information leaked in response headers or error pages "
                            + "allows an attacker to research specific CVEs and deploy precision exploits "
                            + "against the identified software versions.",
                    nodes, edges,
                    "Server compromise via version-specific CVE exploitation",
                    "Remove Server, X-Powered-By, and other version-revealing headers"));
        }

        return chains;
    }

    /**
     * Chain: Dangerous HTTP Methods → Data Tampering / Cross-Site Tracing
     */
    private List<AttackChain> buildDangerousHttpMethodChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> methods = classified.getOrDefault(VulnerabilityCategory.DANGEROUS_HTTP_METHOD, List.of());

        if (!methods.isEmpty()) {
            boolean hasTrace = methods.stream()
                    .anyMatch(v -> v.getName().toUpperCase().contains("TRACE"));
            boolean hasPutOrDelete = methods.stream()
                    .anyMatch(v -> v.getName().toUpperCase().contains("PUT") || v.getName().toUpperCase().contains("DELETE"));

            if (hasTrace) {
                List<AttackChainNode> nodes = new ArrayList<>();
                List<AttackChainEdge> edges = new ArrayList<>();

                AttackChainNode n1 = createCategoryNode(VulnerabilityCategory.DANGEROUS_HTTP_METHOD, Severity.MEDIUM, 0,
                        "TRACE Method Enabled",
                        "Send TRACE request to the server which echoes back the full request including headers",
                        "Server reflects all request headers in the response body");
                AttackChainNode n2 = createCategoryNode(VulnerabilityCategory.SESSION_HIJACKING, Severity.HIGH, 1,
                        "Cross-Site Tracing (XST)",
                        "Use JavaScript (via XSS or malicious page) to issue TRACE and read HttpOnly cookies from the echoed response",
                        "HttpOnly cookie protection is bypassed");
                AttackChainNode n3 = createImpactNode(2, "Session Token Theft",
                        "Extract session cookies that were supposed to be protected by HttpOnly flag",
                        "Attacker obtains authenticated session tokens");

                nodes.addAll(List.of(n1, n2, n3));
                edges.add(createEdge(n1, n2, "enables", "TRACE echoes HttpOnly cookies in response body", 0.65));
                edges.add(createEdge(n2, n3, "leads to", "Bypassed HttpOnly allows cookie theft", 0.7));

                chains.add(buildChain("TRACE Method → Cross-Site Tracing → Session Theft",
                        "The TRACE HTTP method is enabled, allowing an attacker to perform Cross-Site Tracing (XST) "
                                + "attacks that bypass HttpOnly cookie protections and steal session tokens.",
                        nodes, edges, "Session hijacking via HttpOnly cookie bypass",
                        "Disable TRACE method on the web server"));
            }

            if (hasPutOrDelete) {
                List<AttackChainNode> nodes = new ArrayList<>();
                List<AttackChainEdge> edges = new ArrayList<>();

                AttackChainNode n1 = createCategoryNode(VulnerabilityCategory.DANGEROUS_HTTP_METHOD, Severity.LOW, 0,
                        "PUT/DELETE Methods Allowed",
                        "Use PUT to upload malicious files or modify resources; use DELETE to remove critical data",
                        "Server accepts resource modification/deletion requests");
                AttackChainNode n2 = createImpactNode(1, "Unauthorized Data Tampering",
                        "Modify or destroy application data without proper authorization checks",
                        "Data integrity compromised — resources modified or deleted");

                nodes.addAll(List.of(n1, n2));
                edges.add(createEdge(n1, n2, "enables", "Unrestricted methods allow direct resource manipulation", 0.55));

                chains.add(buildChain("PUT/DELETE Methods → Unauthorized Data Tampering",
                        "Dangerous HTTP methods (PUT, DELETE) are not restricted, potentially allowing "
                                + "attackers to modify or delete server resources directly.",
                        nodes, edges, "Data integrity compromise via unrestricted HTTP methods",
                        "Restrict HTTP methods to GET and POST only; return 405 for others"));
            }
        }

        return chains;
    }

    /**
     * Chain: CORS Misconfiguration (standalone) → Cross-Origin Data Theft
     * Fires even without XSS present.
     */
    private List<AttackChain> buildCorsStandaloneChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();
        List<Vulnerability> cors = classified.getOrDefault(VulnerabilityCategory.CORS_MISCONFIGURATION, List.of());
        List<Vulnerability> xss = classified.getOrDefault(VulnerabilityCategory.XSS, List.of());

        // Only standalone — skip if XSS is present (handled by the combo chain)
        if (!cors.isEmpty() && xss.isEmpty()) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();

            AttackChainNode n1 = createNode(cors.getFirst(), 0,
                    "Host a malicious web page on attacker's domain",
                    "CORS policy allows attacker's origin to make cross-origin requests");
            AttackChainNode n2 = createCategoryNode(VulnerabilityCategory.DATA_EXFILTRATION, Severity.MEDIUM, 1,
                    "Cross-Origin API Abuse",
                    "Use JavaScript on attacker's page to fetch authenticated API responses from the target",
                    "Victim's browser sends cookies/tokens with the cross-origin request");
            AttackChainNode n3 = createImpactNode(2, "Sensitive Data Exposure",
                    "Read API responses containing user data, tokens, or internal information",
                    "Authenticated data stolen via cross-origin requests");

            nodes.addAll(List.of(n1, n2, n3));
            edges.add(createEdge(n1, n2, "allows", "Permissive CORS permits cross-origin authenticated requests", 0.7));
            edges.add(createEdge(n2, n3, "exfiltrates", "API responses with sensitive data are readable cross-origin", 0.75));

            chains.add(buildChain("CORS Misconfiguration → Cross-Origin API Abuse → Data Theft",
                    "The server's CORS policy allows untrusted origins to make authenticated requests. "
                            + "An attacker can host a page that silently fetches sensitive API data "
                            + "using the victim's browser session.",
                    nodes, edges, "Sensitive data exposure via cross-origin authenticated requests",
                    "Restrict Access-Control-Allow-Origin to specific trusted domains"));
        }

        return chains;
    }

    /**
     * Chain: Security Posture Degradation — combines missing headers with info disclosure
     * and/or dangerous methods when no high-severity vulns exist.
     * This is the "catch-all" for targets that only have low/medium findings.
     */
    private List<AttackChain> buildSecurityPostureDegradationChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();

        List<Vulnerability> headers = classified.getOrDefault(VulnerabilityCategory.MISSING_HEADER, List.of());
        List<Vulnerability> info = classified.getOrDefault(VulnerabilityCategory.INFORMATION_DISCLOSURE, List.of());
        List<Vulnerability> methods = classified.getOrDefault(VulnerabilityCategory.DANGEROUS_HTTP_METHOD, List.of());
        List<Vulnerability> ssl = classified.getOrDefault(VulnerabilityCategory.SSL_TLS_WEAKNESS, List.of());

        // Only build if we have headers AND at least one other passive category
        boolean hasSecondary = !info.isEmpty() || !methods.isEmpty() || !ssl.isEmpty();
        if (!headers.isEmpty() && hasSecondary) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();
            int depth = 0;

            // Reconnaissance via info disclosure
            if (!info.isEmpty()) {
                AttackChainNode n = createNode(info.getFirst(), depth++,
                        "Fingerprint server technology from leaked version headers",
                        "Attacker knows exact server software and versions");
                nodes.add(n);
            }

            // Weakened defenses via missing headers
            AttackChainNode headerNode = createCategoryNode(VulnerabilityCategory.MISSING_HEADER, Severity.MEDIUM, depth++,
                    "Weakened Browser Defenses (" + headers.size() + " missing headers)",
                    "Map missing security headers to identify unprotected attack vectors",
                    "Multiple browser-side protections are absent");
            if (!nodes.isEmpty()) {
                edges.add(createEdge(nodes.getLast(), headerNode, "reveals", "Server fingerprint reveals which headers to probe", 0.7));
            }
            nodes.add(headerNode);

            // Method abuse if available
            if (!methods.isEmpty()) {
                AttackChainNode methodNode = createNode(methods.getFirst(), depth++,
                        "Probe dangerous HTTP methods for additional attack surface",
                        "Server accepts potentially destructive requests");
                edges.add(createEdge(nodes.getLast(), methodNode, "expands to", "Weak posture invites deeper probing of allowed methods", 0.6));
                nodes.add(methodNode);
            }

            // SSL issues amplify everything
            if (!ssl.isEmpty()) {
                AttackChainNode sslNode = createNode(ssl.getFirst(), depth++,
                        "Identify SSL/TLS weaknesses for traffic interception opportunities",
                        "Encrypted communications can potentially be compromised");
                edges.add(createEdge(nodes.getLast(), sslNode, "compounded by", "Transport-layer weaknesses amplify application-layer issues", 0.6));
                nodes.add(sslNode);
            }

            // Impact
            int totalFindings = headers.size() + info.size() + methods.size() + ssl.size();
            AttackChainNode impact = createImpactNode(depth, "Comprehensive Attack Surface",
                    "Combine " + totalFindings + " findings to build a detailed attack profile for advanced exploitation",
                    "Attacker has a complete map of weaknesses for targeted attacks");
            edges.add(createEdge(nodes.getLast(), impact, "builds to", "Combined weaknesses create a detailed attack blueprint", 0.55));
            nodes.add(impact);

            chains.add(buildChain("Reconnaissance → Defense Mapping → Attack Surface Exposure",
                    "Multiple low and medium severity findings combine to reveal a degraded security posture. "
                            + "Information disclosure aids reconnaissance, missing headers weaken browser defenses, "
                            + "and permissive configurations expand the exploitable attack surface. "
                            + "While no single finding is critical, together they provide an attacker with "
                            + "a comprehensive blueprint for targeted exploitation.",
                    nodes, edges,
                    "Comprehensive attack profile enabling targeted exploitation",
                    "Implement all missing security headers and suppress version information"));
        }

        return chains;
    }

    /**
     * Full kill chain: combines everything found into a worst-case scenario
     * Only built if 2+ different vulnerability categories are present.
     */
    private List<AttackChain> buildFullKillChain(Map<VulnerabilityCategory, List<Vulnerability>> classified) {
        List<AttackChain> chains = new ArrayList<>();

        // Count how many "active" exploit categories we have (excluding MISSING_HEADER as it's passive)
        long activeCategories = classified.entrySet().stream()
                .filter(e -> e.getKey() != VulnerabilityCategory.MISSING_HEADER)
                .filter(e -> !e.getValue().isEmpty())
                .count();

        if (activeCategories >= 2) {
            List<AttackChainNode> nodes = new ArrayList<>();
            List<AttackChainEdge> edges = new ArrayList<>();
            int depth = 0;

            // Reconnaissance phase
            if (classified.containsKey(VulnerabilityCategory.INFORMATION_DISCLOSURE)) {
                AttackChainNode n = createCategoryNode(VulnerabilityCategory.INFORMATION_DISCLOSURE, Severity.LOW, depth++,
                        "Reconnaissance",
                        "Enumerate technology stack from leaked headers and error messages",
                        "Complete fingerprint of target technology stack");
                nodes.add(n);
            }

            // Initial access phase
            AttackChainNode accessNode = null;
            if (classified.containsKey(VulnerabilityCategory.XSS)) {
                accessNode = createCategoryNode(VulnerabilityCategory.XSS, Severity.HIGH, depth++,
                        "Initial Access via XSS",
                        "Deliver XSS payload to gain browser-level execution",
                        "Script execution in user's browser");
            } else if (classified.containsKey(VulnerabilityCategory.SQL_INJECTION)) {
                accessNode = createCategoryNode(VulnerabilityCategory.SQL_INJECTION, Severity.CRITICAL, depth++,
                        "Initial Access via SQLi",
                        "Exploit SQL injection to access backend data",
                        "Database-level access achieved");
            } else if (classified.containsKey(VulnerabilityCategory.OPEN_REDIRECT)) {
                accessNode = createCategoryNode(VulnerabilityCategory.OPEN_REDIRECT, Severity.MEDIUM, depth++,
                        "Initial Access via Redirect",
                        "Use open redirect to deliver phishing attack",
                        "User redirected to attacker-controlled site");
            }

            if (accessNode != null) {
                if (!nodes.isEmpty()) {
                    edges.add(createEdge(nodes.getLast(), accessNode, "informs", "Recon data guides initial exploit", 0.7));
                }
                nodes.add(accessNode);
            }

            // Lateral movement / escalation
            if (classified.containsKey(VulnerabilityCategory.CORS_MISCONFIGURATION)) {
                AttackChainNode n = createCategoryNode(VulnerabilityCategory.CORS_MISCONFIGURATION, Severity.MEDIUM, depth++,
                        "Lateral Movement via CORS",
                        "Leverage CORS to access cross-origin API endpoints",
                        "Access to additional API data and endpoints");
                if (!nodes.isEmpty()) {
                    edges.add(createEdge(nodes.getLast(), n, "enables", "Initial access + CORS allows cross-origin exploitation", 0.65));
                }
                nodes.add(n);
            }

            // Impact
            AttackChainNode impact = createImpactNode(depth, "Full Compromise",
                    "Combine all exploits for maximum impact: data theft, account takeover, potential RCE",
                    "Complete application and data compromise");
            if (!nodes.isEmpty()) {
                edges.add(createEdge(nodes.getLast(), impact, "results in", "Combined exploits achieve full compromise", 0.6));
            }
            nodes.add(impact);

            if (nodes.size() >= 3) {
                chains.add(buildChain("Full Kill Chain: Recon → Exploit → Escalate → Compromise",
                        "Multiple vulnerabilities combine into a full attack kill chain. "
                                + "An attacker can progress from reconnaissance through initial access, "
                                + "lateral movement, and escalation to achieve full application compromise.",
                        nodes, edges, "Complete application, data, and potentially server compromise",
                        "Address CRITICAL and HIGH severity vulnerabilities first to break the kill chain"));
            }
        }

        return chains;
    }

    // ===================== HELPERS =====================

    private Map<VulnerabilityCategory, List<Vulnerability>> classifyVulnerabilities(List<Vulnerability> vulnerabilities) {
        Map<VulnerabilityCategory, List<Vulnerability>> classified = new EnumMap<>(VulnerabilityCategory.class);

        for (Vulnerability v : vulnerabilities) {
            VulnerabilityCategory cat = categorize(v);
            classified.computeIfAbsent(cat, k -> new ArrayList<>()).add(v);
        }

        return classified;
    }

    private VulnerabilityCategory categorize(Vulnerability v) {
        String name = v.getName().toLowerCase();

        if (name.contains("missing security header") || name.contains("missing") && name.contains("header")) {
            return VulnerabilityCategory.MISSING_HEADER;
        }
        if (name.contains("cors")) {
            return VulnerabilityCategory.CORS_MISCONFIGURATION;
        }
        if (name.contains("xss") || name.contains("cross-site scripting")) {
            return VulnerabilityCategory.XSS;
        }
        if (name.contains("sql injection") || name.contains("sqli")) {
            return VulnerabilityCategory.SQL_INJECTION;
        }
        if (name.contains("open redirect")) {
            return VulnerabilityCategory.OPEN_REDIRECT;
        }
        if (name.contains("information disclosure") || name.contains("stack trace") || name.contains("version")) {
            return VulnerabilityCategory.INFORMATION_DISCLOSURE;
        }
        if (name.contains("http method") || name.contains("trace") || name.contains("dangerous")) {
            return VulnerabilityCategory.DANGEROUS_HTTP_METHOD;
        }
        if (name.contains("ssl") || name.contains("tls") || name.contains("certificate") || name.contains("https")) {
            return VulnerabilityCategory.SSL_TLS_WEAKNESS;
        }

        return VulnerabilityCategory.OTHER;
    }

    private AttackChainNode createNode(Vulnerability vuln, int depth, String attackerAction, String outcome) {
        return AttackChainNode.builder()
                .id("node-" + nodeCounter.incrementAndGet())
                .label(vuln.getName())
                .vulnerabilityName(vuln.getName())
                .category(categorize(vuln))
                .severity(vuln.getSeverity())
                .attackerAction(attackerAction)
                .outcome(outcome)
                .depth(depth)
                .build();
    }

    private AttackChainNode createCategoryNode(VulnerabilityCategory category, Severity severity,
                                               int depth, String label, String attackerAction, String outcome) {
        return AttackChainNode.builder()
                .id("node-" + nodeCounter.incrementAndGet())
                .label(label)
                .vulnerabilityName(label)
                .category(category)
                .severity(severity)
                .attackerAction(attackerAction)
                .outcome(outcome)
                .depth(depth)
                .build();
    }

    private AttackChainNode createImpactNode(int depth, String label, String attackerAction, String outcome) {
        return AttackChainNode.builder()
                .id("node-" + nodeCounter.incrementAndGet())
                .label("⚠ IMPACT: " + label)
                .vulnerabilityName(label)
                .category(VulnerabilityCategory.OTHER)
                .severity(Severity.CRITICAL)
                .attackerAction(attackerAction)
                .outcome(outcome)
                .depth(depth)
                .build();
    }

    private AttackChainEdge createEdge(AttackChainNode from, AttackChainNode to,
                                       String label, String description, double confidence) {
        return AttackChainEdge.builder()
                .from(from.getId())
                .to(to.getId())
                .label(label)
                .description(description)
                .confidence(confidence)
                .build();
    }

    private AttackChain buildChain(String title, String description,
                                   List<AttackChainNode> nodes, List<AttackChainEdge> edges,
                                   String impact, String priorityRemediation) {
        Severity maxSev = nodes.stream()
                .map(AttackChainNode::getSeverity)
                .min(Comparator.comparingInt(Enum::ordinal)) // CRITICAL = 0, lowest ordinal = highest severity
                .orElse(Severity.INFO);

        double riskScore = computeRiskScore(nodes, edges);

        return AttackChain.builder()
                .id("chain-" + chainCounter.incrementAndGet())
                .title(title)
                .description(description)
                .nodes(nodes)
                .edges(edges)
                .maxSeverity(maxSev)
                .riskScore(Math.round(riskScore * 10.0) / 10.0)
                .chainLength(nodes.size())
                .impact(impact)
                .priorityRemediation(priorityRemediation)
                .build();
    }

    private double computeRiskScore(List<AttackChainNode> nodes, List<AttackChainEdge> edges) {
        // Base score from severities
        double severityScore = nodes.stream()
                .mapToDouble(n -> switch (n.getSeverity()) {
                    case CRITICAL -> 10.0;
                    case HIGH -> 8.0;
                    case MEDIUM -> 5.0;
                    case LOW -> 3.0;
                    case INFO -> 1.0;
                })
                .max()
                .orElse(0);

        // Average confidence of edges
        double avgConfidence = edges.stream()
                .mapToDouble(AttackChainEdge::getConfidence)
                .average()
                .orElse(0.5);

        // Chain length factor: shorter chains are more exploitable
        double lengthFactor = Math.max(0.5, 1.0 - (nodes.size() - 2) * 0.1);

        // Composite: base * confidence * length, scaled to 0-100
        return severityScore * avgConfidence * lengthFactor * 10.0;
    }

    private String computeThreatLevel(double maxRisk, int chainCount) {
        if (maxRisk >= 80 || chainCount >= 5) return "CRITICAL";
        if (maxRisk >= 60 || chainCount >= 3) return "HIGH";
        if (maxRisk >= 40 || chainCount >= 2) return "MEDIUM";
        if (maxRisk >= 20) return "LOW";
        return chainCount == 0 ? "NONE" : "INFORMATIONAL";
    }

    private List<AttackChain> deduplicateChains(List<AttackChain> chains) {
        Map<String, AttackChain> unique = new LinkedHashMap<>();
        for (AttackChain chain : chains) {
            String key = chain.getNodes().stream()
                    .map(AttackChainNode::getLabel)
                    .sorted()
                    .collect(Collectors.joining("|"));
            unique.merge(key, chain, (existing, newer) ->
                    newer.getRiskScore() > existing.getRiskScore() ? newer : existing);
        }
        return new ArrayList<>(unique.values());
    }
}

