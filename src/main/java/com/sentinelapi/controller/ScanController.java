package com.sentinelapi.controller;

import com.sentinelapi.dto.AttackChainVisualization;
import com.sentinelapi.dto.ScanRequest;
import com.sentinelapi.dto.VulnerabilityReport;
import com.sentinelapi.dto.graph.GraphExportResponse;
import com.sentinelapi.service.GraphExportService;
import com.sentinelapi.service.ScanService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;
    private final GraphExportService graphExportService;

    @PostMapping("/scan")
    public ResponseEntity<VulnerabilityReport> scan(@Valid @RequestBody ScanRequest request) {
        VulnerabilityReport report = scanService.scan(request.getTargetUrl());
        return ResponseEntity.ok(report);
    }

    @PostMapping("/scan/attack-chains")
    public ResponseEntity<AttackChainVisualization> attackChains(@Valid @RequestBody ScanRequest request) {
        VulnerabilityReport report = scanService.scan(request.getTargetUrl());
        return ResponseEntity.ok(report.getAttackChainVisualization());
    }


    @PostMapping("/scan/export-graph")
    public ResponseEntity<GraphExportResponse> exportGraph(@Valid @RequestBody ScanRequest request) {
        VulnerabilityReport report = scanService.scan(request.getTargetUrl());
        GraphExportResponse graph = graphExportService.export(report.getAttackChainVisualization());
        return ResponseEntity.ok(graph);
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("SentinelAPI is running");
    }
}

