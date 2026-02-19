package com.sentinelapi.dto.graph;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Complete graph export payload, ready for React Flow rendering.
 *
 * Usage in React:
 * <pre>
 *   const { nodes, edges } = await fetch('/api/scan/export-graph', ...);
 *   &lt;ReactFlow nodes={nodes} edges={edges} ... /&gt;
 * </pre>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GraphExportResponse {

    /** Target URL that was scanned */
    private String targetUrl;

    /** React Flow nodes — ready to pass directly to <ReactFlow nodes={...} /> */
    private List<GraphExportNode> nodes;

    /** React Flow edges — ready to pass directly to <ReactFlow edges={...} /> */
    private List<GraphExportEdge> edges;

    /** Layout metadata */
    private GraphLayout layout;

    /** Legend mapping severity → color */
    private Map<String, String> severityColorMap;

    /** Legend mapping node type → description */
    private Map<String, String> nodeTypeLegend;

    /** Graph statistics */
    private GraphStats stats;

    /** Per-chain summary (for sidebar / accordion in React) */
    private List<ChainSummary> chainSummaries;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GraphLayout {
        /** Layout algorithm used: "dagre", "elkjs", "manual" */
        private String algorithm;
        /** Layout direction: "TB" (top-bottom), "LR" (left-right) */
        private String direction;
        /** Horizontal spacing between nodes */
        private double nodeSpacingX;
        /** Vertical spacing between nodes */
        private double nodeSpacingY;
        /** Total width of the laid-out graph */
        private double graphWidth;
        /** Total height of the laid-out graph */
        private double graphHeight;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GraphStats {
        private int totalNodes;
        private int totalEdges;
        private int totalChains;
        private double maxRiskScore;
        private String overallThreatLevel;
        private String topRemediation;
        private int chainsBlockedByTopRemediation;
        /** Node count per severity */
        private Map<String, Integer> nodesBySeverity;
        /** Node count per category */
        private Map<String, Integer> nodesByCategory;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ChainSummary {
        private String chainId;
        private String title;
        private String description;
        private double riskScore;
        private String maxSeverity;
        private int chainLength;
        private String impact;
        private String priorityRemediation;
        /** IDs of nodes in this chain — for highlighting on hover/click */
        private List<String> nodeIds;
        /** IDs of edges in this chain — for highlighting on hover/click */
        private List<String> edgeIds;
    }
}

