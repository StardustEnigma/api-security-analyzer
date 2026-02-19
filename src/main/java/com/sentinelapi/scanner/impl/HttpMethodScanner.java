package com.sentinelapi.scanner.impl;

import com.sentinelapi.dto.Vulnerability;
import com.sentinelapi.model.Severity;
import com.sentinelapi.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class HttpMethodScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final List<HttpMethod> DANGEROUS_METHODS = List.of(
            HttpMethod.TRACE,
            HttpMethod.DELETE,
            HttpMethod.PUT
    );

    @Override
    public String getName() {
        return "HTTP Method Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Check OPTIONS to see what's advertised
        try {
            var optionsResponse = webClient.options()
                    .uri(targetUrl)
                    .exchangeToMono(response -> {
                        String allow = response.headers().asHttpHeaders().getFirst("Allow");
                        return reactor.core.publisher.Mono.justOrEmpty(allow);
                    })
                    .block();

            if (optionsResponse != null && !optionsResponse.isBlank()) {
                String allowUpper = optionsResponse.toUpperCase();
                if (allowUpper.contains("TRACE")) {
                    vulnerabilities.add(Vulnerability.builder()
                            .name("TRACE Method Enabled (OPTIONS)")
                            .severity(Severity.MEDIUM)
                            .description("The server advertises TRACE method support via OPTIONS. TRACE can be exploited for Cross-Site Tracing (XST) attacks.")
                            .evidence("OPTIONS Allow header: " + optionsResponse)
                            .remediation("Disable TRACE method on the server.")
                            .build());
                }
            }
        } catch (Exception e) {
            log.debug("OPTIONS check failed for {}: {}", targetUrl, e.getMessage());
        }

        // Probe each dangerous method directly
        for (HttpMethod method : DANGEROUS_METHODS) {
            try {
                HttpStatusCode status = webClient.method(method)
                        .uri(targetUrl)
                        .exchangeToMono(response ->
                                reactor.core.publisher.Mono.just(response.statusCode()))
                        .block();

                if (status != null && !status.equals(HttpStatusCode.valueOf(405))
                        && !status.equals(HttpStatusCode.valueOf(501))) {
                    vulnerabilities.add(Vulnerability.builder()
                            .name("Dangerous HTTP Method Allowed: " + method.name())
                            .severity(method == HttpMethod.TRACE ? Severity.MEDIUM : Severity.LOW)
                            .description("The server responded to " + method.name() + " with status " + status.value()
                                    + " instead of 405 Method Not Allowed.")
                            .evidence(method.name() + " " + targetUrl + " → HTTP " + status.value())
                            .remediation("Restrict HTTP methods to only those required (typically GET and POST). Return 405 for unsupported methods.")
                            .build());
                }
            } catch (Exception e) {
                log.debug("{} method check failed for {}: {}", method, targetUrl, e.getMessage());
            }
        }

        return vulnerabilities;
    }
}

