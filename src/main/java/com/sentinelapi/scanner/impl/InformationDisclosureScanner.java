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
public class InformationDisclosureScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final Map<String, String> VERSION_HEADERS = Map.of(
            "Server", "Server version information disclosed",
            "X-Powered-By", "Technology stack disclosed via X-Powered-By",
            "X-AspNet-Version", "ASP.NET version disclosed",
            "X-AspNetMvc-Version", "ASP.NET MVC version disclosed"
    );

    private static final List<String> STACK_TRACE_SIGNATURES = List.of(
            "stack trace",
            "stacktrace",
            "at java.",
            "at org.springframework",
            "at sun.",
            "traceback (most recent call last)",
            "file \"",
            "exception in thread",
            "caused by:",
            "error occurred while processing",
            "unhandled exception",
            "fatal error",
            "debug mode",
            "phpinfo()"
    );

    @Override
    public String getName() {
        return "Information Disclosure Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Check response headers for version information
        try {
            HttpHeaders headers = webClient.get()
                    .uri(targetUrl)
                    .exchangeToMono(response ->
                            reactor.core.publisher.Mono.just(response.headers().asHttpHeaders()))
                    .block();

            if (headers != null) {
                for (Map.Entry<String, String> entry : VERSION_HEADERS.entrySet()) {
                    String headerValue = headers.getFirst(entry.getKey());
                    if (headerValue != null && !headerValue.isBlank()) {
                        // Only flag if version-like info is present (contains a digit)
                        if (headerValue.matches(".*\\d.*")) {
                            vulnerabilities.add(Vulnerability.builder()
                                    .name("Information Disclosure: " + entry.getKey())
                                    .severity(Severity.LOW)
                                    .description(entry.getValue()
                                            + ". Attackers can use this information to target known vulnerabilities.")
                                    .evidence(entry.getKey() + ": " + headerValue)
                                    .remediation("Remove or suppress the " + entry.getKey()
                                            + " header to prevent version disclosure.")
                                    .build());
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Header disclosure check failed: {}", e.getMessage());
        }

        // Trigger error pages and check for stack traces
        List<String> errorPaths = List.of(
                targetUrl + "/../../../../etc/passwd",
                targetUrl + "/'",
                targetUrl + "/nonexistent-" + System.currentTimeMillis(),
                targetUrl + "/%00"
        );

        for (String errorUrl : errorPaths) {
            try {
                String body = webClient.get()
                        .uri(errorUrl)
                        .retrieve()
                        .bodyToMono(String.class)
                        .onErrorReturn("")
                        .block();

                if (body != null && !body.isEmpty()) {
                    String bodyLower = body.toLowerCase();
                    for (String signature : STACK_TRACE_SIGNATURES) {
                        if (bodyLower.contains(signature)) {
                            vulnerabilities.add(Vulnerability.builder()
                                    .name("Information Disclosure: Stack Trace / Debug Info")
                                    .severity(Severity.MEDIUM)
                                    .description("The application exposes stack traces or debug information in error responses. "
                                            + "This reveals implementation details useful to attackers.")
                                    .evidence("Signature found: '" + signature + "' in response from: " + errorUrl)
                                    .remediation("Configure custom error pages. Disable debug mode in production. "
                                            + "Never expose stack traces to end users.")
                                    .build());
                            return vulnerabilities;
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("Error page check failed for {}: {}", errorUrl, e.getMessage());
            }
        }

        return vulnerabilities;
    }
}

