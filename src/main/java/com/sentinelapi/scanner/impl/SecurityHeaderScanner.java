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
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityHeaderScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final Map<String, HeaderCheck> SECURITY_HEADERS = Map.of(
            "Strict-Transport-Security", new HeaderCheck(Severity.HIGH,
                    "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks.",
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."),
            "Content-Security-Policy", new HeaderCheck(Severity.MEDIUM,
                    "Content-Security-Policy header is missing. This increases risk of XSS attacks.",
                    "Implement a Content-Security-Policy header with appropriate directives."),
            "X-Content-Type-Options", new HeaderCheck(Severity.MEDIUM,
                    "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses.",
                    "Add 'X-Content-Type-Options: nosniff' header."),
            "X-Frame-Options", new HeaderCheck(Severity.MEDIUM,
                    "X-Frame-Options header is missing. The site may be vulnerable to clickjacking.",
                    "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."),
            "X-XSS-Protection", new HeaderCheck(Severity.LOW,
                    "X-XSS-Protection header is missing.",
                    "Add 'X-XSS-Protection: 1; mode=block' header (legacy browsers)."),
            "Referrer-Policy", new HeaderCheck(Severity.LOW,
                    "Referrer-Policy header is missing. Referrer information may leak to third parties.",
                    "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."),
            "Permissions-Policy", new HeaderCheck(Severity.LOW,
                    "Permissions-Policy header is missing. Browser features are not restricted.",
                    "Add a Permissions-Policy header to restrict unnecessary browser features.")
    );

    @Override
    public String getName() {
        return "Security Header Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            HttpHeaders headers = webClient.get()
                    .uri(targetUrl)
                    .exchangeToMono(response -> {
                        return reactor.core.publisher.Mono.just(response.headers().asHttpHeaders());
                    })
                    .block();

            if (headers == null) {
                return vulnerabilities;
            }

            for (Map.Entry<String, HeaderCheck> entry : SECURITY_HEADERS.entrySet()) {
                String headerName = entry.getKey();
                HeaderCheck check = entry.getValue();

                if (!headers.containsKey(headerName)) {
                    vulnerabilities.add(Vulnerability.builder()
                            .name("Missing Security Header: " + headerName)
                            .severity(check.severity())
                            .description(check.description())
                            .evidence("Header '" + headerName + "' was not found in the response.")
                            .remediation(check.remediation())
                            .build());
                }
            }
        } catch (Exception e) {
            log.warn("Security header scan failed for {}: {}", targetUrl, e.getMessage());
        }

        return vulnerabilities;
    }

    private record HeaderCheck(Severity severity, String description, String remediation) {}
}

