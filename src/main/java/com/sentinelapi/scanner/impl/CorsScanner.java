package com.sentinelapi.scanner.impl;

import com.sentinelapi.dto.Vulnerability;
import com.sentinelapi.model.Severity;
import com.sentinelapi.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class CorsScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final String EVIL_ORIGIN = "https://evil.com";

    @Override
    public String getName() {
        return "CORS Misconfiguration Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            HttpHeaders headers = webClient.get()
                    .uri(targetUrl)
                    .header("Origin", EVIL_ORIGIN)
                    .exchangeToMono(response ->
                            reactor.core.publisher.Mono.just(response.headers().asHttpHeaders()))
                    .block();

            if (headers == null) return vulnerabilities;

            String acao = headers.getFirst("Access-Control-Allow-Origin");
            String acac = headers.getFirst("Access-Control-Allow-Credentials");

            if (acao != null) {
                // Wildcard CORS
                if ("*".equals(acao)) {
                    vulnerabilities.add(Vulnerability.builder()
                            .name("CORS Wildcard Origin")
                            .severity(Severity.MEDIUM)
                            .description("The server allows any origin (*) to access its resources via CORS. "
                                    + "This may expose sensitive data to unauthorized domains.")
                            .evidence("Access-Control-Allow-Origin: *")
                            .remediation("Restrict Access-Control-Allow-Origin to specific trusted domains "
                                    + "instead of using a wildcard.")
                            .build());
                }

                // Reflected evil origin
                if (acao.contains("evil.com")) {
                    Severity severity = "true".equalsIgnoreCase(acac) ? Severity.HIGH : Severity.MEDIUM;
                    String extraDesc = "true".equalsIgnoreCase(acac)
                            ? " Combined with Access-Control-Allow-Credentials: true, this allows an attacker to steal authenticated data."
                            : "";

                    vulnerabilities.add(Vulnerability.builder()
                            .name("CORS Origin Reflection")
                            .severity(severity)
                            .description("The server reflects the Origin header value in Access-Control-Allow-Origin. "
                                    + "An attacker's domain can make cross-origin requests to this API." + extraDesc)
                            .evidence("Origin sent: " + EVIL_ORIGIN + " | Access-Control-Allow-Origin: " + acao
                                    + (acac != null ? " | Access-Control-Allow-Credentials: " + acac : ""))
                            .remediation("Validate the Origin header against a strict allowlist. "
                                    + "Never reflect arbitrary origins. If credentials are needed, "
                                    + "ensure only trusted origins are allowed.")
                            .build());
                }
            }
        } catch (Exception e) {
            log.warn("CORS scan failed for {}: {}", targetUrl, e.getMessage());
        }

        return vulnerabilities;
    }
}

