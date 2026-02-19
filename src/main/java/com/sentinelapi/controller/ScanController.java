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

    /**
     * Full security scan including attack chain visualization.
     */
    @PostMapping("/scan")
    public ResponseEntity<VulnerabilityReport> scan(@Valid @RequestBody ScanRequest request) {
        VulnerabilityReport report = scanService.scan(request.getTargetUrl());
        return ResponseEntity.ok(report);
    }

    /**
     * Scan and return ONLY the attack chain visualization.
     * Useful when the frontend only needs the graph data.
     */
    @PostMapping("/scan/attack-chains")
    public ResponseEntity<AttackChainVisualization> attackChains(@Valid @RequestBody ScanRequest request) {
        VulnerabilityReport report = scanService.scan(request.getTargetUrl());
        return ResponseEntity.ok(report.getAttackChainVisualization());
    }

    /**
     * Scan and return the attack graph in React Flow-compatible format.
     *
     * Response contains:
     * - nodes[] → pass directly to {@code <ReactFlow nodes={nodes} />}
     * - edges[] → pass directly to {@code <ReactFlow edges={edges} />}
     * - layout  → graph dimensions and spacing hints
     * - severityColorMap → severity-to-hex color mapping for legends
     * - nodeTypeLegend   → node type descriptions
     * - stats            → summary statistics for dashboard cards
     * - chainSummaries[] → per-chain info with nodeIds/edgeIds for highlight on hover
     */
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

