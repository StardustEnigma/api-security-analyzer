package com.sentinelapi.dto.graph;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GraphExportResponse {

    private String targetUrl;

    private List<GraphExportNode> nodes;

    private List<GraphExportEdge> edges;

    private GraphLayout layout;

    private Map<String, String> severityColorMap;

    private Map<String, String> nodeTypeLegend;

    private GraphStats stats;

    private List<ChainSummary> chainSummaries;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class GraphLayout {
        private String algorithm;
        private String direction;
        private double nodeSpacingX;
        private double nodeSpacingY;
        private double graphWidth;
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
        private Map<String, Integer> nodesBySeverity;
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
        private List<String> nodeIds;
        private List<String> edgeIds;
    }
}

