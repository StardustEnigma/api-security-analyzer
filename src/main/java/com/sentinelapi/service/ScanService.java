package com.sentinelapi.service;

import com.sentinelapi.dto.Vulnerability;
import com.sentinelapi.dto.VulnerabilityReport;
import com.sentinelapi.engine.AttackChainEngine;
import com.sentinelapi.model.Severity;
import com.sentinelapi.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanService {

    private final List<SecurityScanner> scanners;
    private final AttackChainEngine attackChainEngine;

    public VulnerabilityReport scan(String targetUrl) {
        log.info("Starting security scan for: {}", targetUrl);
        long startTime = System.currentTimeMillis();

        // Normalize URL
        String normalizedUrl = targetUrl.trim();
        if (normalizedUrl.endsWith("/")) {
            normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length() - 1);
        }

        final String url = normalizedUrl;

        // Execute all scanners in parallel
        List<CompletableFuture<List<Vulnerability>>> futures = scanners.stream()
                .map(scanner -> CompletableFuture.supplyAsync(() -> {
                    try {
                        log.info("Running scanner: {}", scanner.getName());
                        List<Vulnerability> results = scanner.scan(url);
                        log.info("Scanner '{}' found {} vulnerabilities", scanner.getName(), results.size());
                        return results;
                    } catch (Exception e) {
                        log.error("Scanner '{}' failed: {}", scanner.getName(), e.getMessage());
                        return Collections.<Vulnerability>emptyList();
                    }
                }))
                .toList();

        // Collect all results
        List<Vulnerability> allVulnerabilities = futures.stream()
                .map(CompletableFuture::join)
                .flatMap(List::stream)
                .collect(Collectors.toCollection(ArrayList::new));

        // Sort by severity (CRITICAL first)
        allVulnerabilities.sort((a, b) -> a.getSeverity().compareTo(b.getSeverity()));

        // Build severity summary
        Map<Severity, Long> severitySummary = allVulnerabilities.stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity, Collectors.counting()));

        long scanDuration = System.currentTimeMillis() - startTime;
        log.info("Scan completed for {} in {}ms. Found {} vulnerabilities.",
                url, scanDuration, allVulnerabilities.size());

        // Run attack chain analysis
        var attackChainVisualization = attackChainEngine.analyze(url, allVulnerabilities);

        return VulnerabilityReport.builder()
                .targetUrl(url)
                .scanTimestamp(LocalDateTime.now())
                .totalVulnerabilities(allVulnerabilities.size())
                .severitySummary(severitySummary)
                .vulnerabilities(allVulnerabilities)
                .scanDurationMs(scanDuration)
                .attackChainVisualization(attackChainVisualization)
                .build();
    }
}

