package com.sentinelapi.scanner.impl;

import com.sentinelapi.dto.Vulnerability;
import com.sentinelapi.model.Severity;
import com.sentinelapi.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class XssScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final List<String> XSS_PAYLOADS = List.of(
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "\"><script>alert('xss')</script>",
            "'><script>alert('xss')</script>",
            "<svg onload=alert('xss')>",
            "javascript:alert('xss')"
    );

    @Override
    public String getName() {
        return "XSS Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String payload : XSS_PAYLOADS) {
            try {
                String testUrl = UriComponentsBuilder.fromUriString(targetUrl)
                        .queryParam("q", payload)
                        .queryParam("search", payload)
                        .queryParam("input", payload)
                        .build()
                        .toUriString();

                String responseBody = webClient.get()
                        .uri(testUrl)
                        .retrieve()
                        .bodyToMono(String.class)
                        .onErrorReturn("")
                        .block();

                if (responseBody != null && responseBody.contains(payload)) {
                    vulnerabilities.add(Vulnerability.builder()
                            .name("Reflected Cross-Site Scripting (XSS)")
                            .severity(Severity.HIGH)
                            .description("The application reflects user input without proper encoding or sanitization. "
                                    + "An attacker could inject malicious scripts that execute in victims' browsers.")
                            .evidence("Payload '" + payload + "' was reflected unencoded in the response body. URL: " + testUrl)
                            .remediation("Encode all user-supplied output using context-appropriate encoding (HTML entity encoding, "
                                    + "JavaScript encoding, URL encoding). Implement Content-Security-Policy headers. "
                                    + "Use frameworks that auto-escape output by default.")
                            .build());
                    return vulnerabilities; // One confirmed finding is enough
                }
            } catch (Exception e) {
                log.debug("XSS test failed for payload '{}': {}", payload, e.getMessage());
            }
        }

        return vulnerabilities;
    }
}

