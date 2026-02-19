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
public class SqlInjectionScanner implements SecurityScanner {

    private final WebClient webClient;

    private static final List<String> SQL_PAYLOADS = List.of(
            "' OR '1'='1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "' OR 1=1#"
    );

    private static final List<String> SQL_ERROR_SIGNATURES = List.of(
            "sql syntax",
            "mysql_",
            "mysqli_",
            "pg_query",
            "ora-",
            "sqlite3",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sql server",
            "microsoft ole db",
            "odbc drivers",
            "syntax error",
            "postgresql",
            "warning: mysql",
            "valid mysql result",
            "sqlstate",
            "jdbc"
    );

    @Override
    public String getName() {
        return "SQL Injection Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String payload : SQL_PAYLOADS) {
            try {
                String testUrl = UriComponentsBuilder.fromUriString(targetUrl)
                        .queryParam("id", payload)
                        .queryParam("q", payload)
                        .build()
                        .toUriString();

                String responseBody = webClient.get()
                        .uri(testUrl)
                        .retrieve()
                        .bodyToMono(String.class)
                        .onErrorReturn("")
                        .block();

                if (responseBody != null && !responseBody.isEmpty()) {
                    String bodyLower = responseBody.toLowerCase();
                    for (String signature : SQL_ERROR_SIGNATURES) {
                        if (bodyLower.contains(signature)) {
                            vulnerabilities.add(Vulnerability.builder()
                                    .name("Potential SQL Injection")
                                    .severity(Severity.CRITICAL)
                                    .description("The application returned a database error message when tested with SQL injection payload. "
                                            + "This suggests the input is being included in SQL queries without proper sanitization.")
                                    .evidence("Payload: " + payload + " | Error signature found: '" + signature
                                            + "' | URL: " + testUrl)
                                    .remediation("Use parameterized queries / prepared statements. Never concatenate user input into SQL queries. "
                                            + "Implement input validation and use an ORM where possible.")
                                    .build());
                            return vulnerabilities; // One confirmed finding is enough
                        }
                    }
                }
            } catch (Exception e) {
                log.debug("SQL injection test failed for payload '{}': {}", payload, e.getMessage());
            }
        }

        return vulnerabilities;
    }
}

