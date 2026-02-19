package com.sentinelapi.scanner.impl;

import com.sentinelapi.dto.Vulnerability;
import com.sentinelapi.model.Severity;
import com.sentinelapi.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class OpenRedirectScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final String EVIL_DOMAIN = "https://evil.com";

    private static final List<String> REDIRECT_PARAMS = List.of(
            "redirect", "url", "next", "dest", "destination",
            "redir", "redirect_uri", "redirect_url", "return",
            "return_url", "returnTo", "go", "goto", "target", "link"
    );

    @Override
    public String getName() {
        return "Open Redirect Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String param : REDIRECT_PARAMS) {
            try {
                String testUrl = UriComponentsBuilder.fromUriString(targetUrl)
                        .queryParam(param, EVIL_DOMAIN)
                        .build()
                        .toUriString();

                ClientResponse response = webClient.get()
                        .uri(testUrl)
                        .exchangeToMono(Mono::just)
                        .block();

                if (response == null) continue;

                HttpStatusCode status = response.statusCode();
                if (status.is3xxRedirection()) {
                    URI location = response.headers().asHttpHeaders().getLocation();
                    String locationStr = location != null ? location.toString() :
                            response.headers().asHttpHeaders().getFirst(HttpHeaders.LOCATION);

                    if (locationStr != null && locationStr.contains("evil.com")) {
                        vulnerabilities.add(Vulnerability.builder()
                                .name("Open Redirect Vulnerability")
                                .severity(Severity.MEDIUM)
                                .description("The application redirects to a user-controlled URL without validation. "
                                        + "An attacker can craft links that redirect users to malicious sites.")
                                .evidence("Parameter '" + param + "' caused redirect to: " + locationStr
                                        + " | Test URL: " + testUrl + " | Status: " + status.value())
                                .remediation("Validate redirect URLs against an allowlist of trusted domains. "
                                        + "Avoid using user input directly in redirect targets. "
                                        + "Use relative paths instead of absolute URLs for redirects.")
                                .build());
                        return vulnerabilities;
                    }
                }
            } catch (Exception e) {
                log.debug("Open redirect test failed for param '{}': {}", param, e.getMessage());
            }
        }

        return vulnerabilities;
    }
}

