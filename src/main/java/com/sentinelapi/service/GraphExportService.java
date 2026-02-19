package com.sentinelapi.service;

import com.sentinelapi.dto.AttackChain;
import com.sentinelapi.dto.AttackChainEdge;
import com.sentinelapi.dto.AttackChainNode;
import com.sentinelapi.dto.AttackChainVisualization;
import com.sentinelapi.dto.graph.GraphExportEdge;
import com.sentinelapi.dto.graph.GraphExportNode;
import com.sentinelapi.dto.graph.GraphExportResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Transforms AttackChainVisualization into a React Flow-compatible
 * graph export format with layout positions, styles, and metadata.
 */
@Slf4j
@Service
public class GraphExportService {

    // ── Severity → Color mapping (used for node borders and background tints) ──
    private static final Map<String, String> SEVERITY_COLORS = new LinkedHashMap<>();
    static {
        SEVERITY_COLORS.put("CRITICAL", "#FF1744");
        SEVERITY_COLORS.put("HIGH",     "#FF6D00");
        SEVERITY_COLORS.put("MEDIUM",   "#FFC400");
        SEVERITY_COLORS.put("LOW",      "#00E676");
        SEVERITY_COLORS.put("INFO",     "#448AFF");
    }

    // ── Severity → Background tint (lighter versions for node fill) ──
    private static final Map<String, String> SEVERITY_BG = Map.of(
            "CRITICAL", "#FFF0F0",
            "HIGH",     "#FFF3E0",
            "MEDIUM",   "#FFFDE7",
            "LOW",      "#E8F5E9",
            "INFO",     "#E3F2FD"
    );

    // ── Node type legend ──
    private static final Map<String, String> NODE_TYPE_LEGEND = new LinkedHashMap<>();
    static {
        NODE_TYPE_LEGEND.put("vulnerability", "A discovered vulnerability that serves as an attack step");
        NODE_TYPE_LEGEND.put("impact",        "The ultimate impact / consequence of the attack chain");
        NODE_TYPE_LEGEND.put("entry",         "The initial entry point of the attack chain (depth 0)");
    }

    // ── Layout constants ──
    private static final double NODE_SPACING_X = 320;
    private static final double NODE_SPACING_Y = 200;
    private static final double CHAIN_GAP_Y = 120;

    /**
     * Convert an AttackChainVisualization into a React Flow-ready export.
     */
    public GraphExportResponse export(AttackChainVisualization viz) {
        log.info("Exporting attack graph for {} ({} chains)", viz.getTargetUrl(), viz.getTotalChains());

        List<GraphExportNode> allNodes = new ArrayList<>();
        List<GraphExportEdge> allEdges = new ArrayList<>();
        List<GraphExportResponse.ChainSummary> chainSummaries = new ArrayList<>();

        // Track node IDs already placed (for dedup across chains sharing nodes)
        Set<String> placedNodeIds = new HashSet<>();
        double currentY = 0;
        double maxX = 0;

        int edgeCounter = 0;

        for (AttackChain chain : viz.getAttackChains()) {

            List<String> chainNodeIds = new ArrayList<>();
            List<String> chainEdgeIds = new ArrayList<>();

            // ── Lay out nodes for this chain ──
            for (AttackChainNode node : chain.getNodes()) {
                if (placedNodeIds.contains(node.getId())) {
                    chainNodeIds.add(node.getId());
                    continue;
                }

                double x = node.getDepth() * NODE_SPACING_X;
                double y = currentY;

                String nodeType = resolveNodeType(node);
                String sev = node.getSeverity().name();

                Map<String, Object> data = new LinkedHashMap<>();
                data.put("label", node.getLabel());
                data.put("vulnerabilityName", node.getVulnerabilityName());
                data.put("category", node.getCategory().name());
                data.put("categoryDisplay", node.getCategory().getDisplayName());
                data.put("severity", sev);
                data.put("attackerAction", node.getAttackerAction());
                data.put("outcome", node.getOutcome());
                data.put("depth", node.getDepth());
                data.put("chainId", chain.getId());
                data.put("isImpact", node.getLabel().startsWith("⚠"));
                data.put("isEntry", node.getDepth() == 0);

                Map<String, String> style = new LinkedHashMap<>();
                style.put("background", SEVERITY_BG.getOrDefault(sev, "#FFFFFF"));
                style.put("border", "2px solid " + SEVERITY_COLORS.getOrDefault(sev, "#9E9E9E"));
                style.put("borderRadius", "12px");
                style.put("padding", "16px");
                style.put("minWidth", "220px");
                style.put("maxWidth", "280px");
                style.put("fontSize", "13px");
                style.put("boxShadow", "0 2px 8px rgba(0,0,0,0.1)");

                if (node.getLabel().startsWith("⚠")) {
                    style.put("border", "3px solid " + SEVERITY_COLORS.get("CRITICAL"));
                    style.put("background", "#FFF0F0");
                    style.put("fontWeight", "bold");
                }

                GraphExportNode exportNode = GraphExportNode.builder()
                        .id(node.getId())
                        .type(nodeType)
                        .position(GraphExportNode.Position.builder().x(x).y(y).build())
                        .data(data)
                        .style(style)
                        .parentId(chain.getId())
                        .build();

                allNodes.add(exportNode);
                placedNodeIds.add(node.getId());
                chainNodeIds.add(node.getId());
                maxX = Math.max(maxX, x);
            }

            // ── Convert edges ──
            for (AttackChainEdge edge : chain.getEdges()) {
                String edgeId = "edge-" + (++edgeCounter);

                String sevColor = resolveEdgeColor(edge.getConfidence());
                boolean isHighConfidence = edge.getConfidence() >= 0.7;

                Map<String, Object> data = new LinkedHashMap<>();
                data.put("description", edge.getDescription());
                data.put("confidence", edge.getConfidence());
                data.put("confidenceLabel", formatConfidence(edge.getConfidence()));
                data.put("chainId", chain.getId());

                Map<String, String> edgeStyle = new LinkedHashMap<>();
                edgeStyle.put("stroke", sevColor);
                edgeStyle.put("strokeWidth", isHighConfidence ? "2.5" : "1.5");

                Map<String, String> labelStyle = new LinkedHashMap<>();
                labelStyle.put("fontSize", "11px");
                labelStyle.put("fontWeight", isHighConfidence ? "600" : "400");
                labelStyle.put("fill", "#333");

                Map<String, String> markerEnd = new LinkedHashMap<>();
                markerEnd.put("type", "arrowclosed");
                markerEnd.put("color", sevColor);

                GraphExportEdge exportEdge = GraphExportEdge.builder()
                        .id(edgeId)
                        .source(edge.getFrom())
                        .target(edge.getTo())
                        .sourceHandle("right")
                        .targetHandle("left")
                        .type("smoothstep")
                        .animated(isHighConfidence)
                        .label(edge.getLabel() + " (" + Math.round(edge.getConfidence() * 100) + "%)")
                        .markerEnd(markerEnd)
                        .style(edgeStyle)
                        .labelStyle(labelStyle)
                        .data(data)
                        .build();

                allEdges.add(exportEdge);
                chainEdgeIds.add(edgeId);
            }

            // ── Chain summary ──
            chainSummaries.add(GraphExportResponse.ChainSummary.builder()
                    .chainId(chain.getId())
                    .title(chain.getTitle())
                    .description(chain.getDescription())
                    .riskScore(chain.getRiskScore())
                    .maxSeverity(chain.getMaxSeverity().name())
                    .chainLength(chain.getChainLength())
                    .impact(chain.getImpact())
                    .priorityRemediation(chain.getPriorityRemediation())
                    .nodeIds(chainNodeIds)
                    .edgeIds(chainEdgeIds)
                    .build());

            currentY += NODE_SPACING_Y + CHAIN_GAP_Y;
        }

        // ── Layout metadata ──
        double graphWidth = maxX + NODE_SPACING_X;
        double graphHeight = currentY > 0 ? currentY - CHAIN_GAP_Y : 0;

        GraphExportResponse.GraphLayout layout = GraphExportResponse.GraphLayout.builder()
                .algorithm("dagre")
                .direction("LR")
                .nodeSpacingX(NODE_SPACING_X)
                .nodeSpacingY(NODE_SPACING_Y)
                .graphWidth(graphWidth)
                .graphHeight(graphHeight)
                .build();

        // ── Stats ──
        Map<String, Integer> nodesBySeverity = allNodes.stream()
                .collect(Collectors.groupingBy(
                        n -> (String) n.getData().get("severity"),
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)));

        Map<String, Integer> nodesByCategory = allNodes.stream()
                .collect(Collectors.groupingBy(
                        n -> (String) n.getData().get("category"),
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)));

        GraphExportResponse.GraphStats stats = GraphExportResponse.GraphStats.builder()
                .totalNodes(allNodes.size())
                .totalEdges(allEdges.size())
                .totalChains(viz.getTotalChains())
                .maxRiskScore(viz.getMaxRiskScore())
                .overallThreatLevel(viz.getOverallThreatLevel())
                .topRemediation(viz.getTopRemediation())
                .chainsBlockedByTopRemediation(viz.getChainsBlockedByTopRemediation())
                .nodesBySeverity(nodesBySeverity)
                .nodesByCategory(nodesByCategory)
                .build();

        log.info("Graph export: {} nodes, {} edges, {} chains",
                allNodes.size(), allEdges.size(), viz.getTotalChains());

        return GraphExportResponse.builder()
                .targetUrl(viz.getTargetUrl())
                .nodes(allNodes)
                .edges(allEdges)
                .layout(layout)
                .severityColorMap(SEVERITY_COLORS)
                .nodeTypeLegend(NODE_TYPE_LEGEND)
                .stats(stats)
                .chainSummaries(chainSummaries)
                .build();
    }

    // ── Helpers ──

    private String resolveNodeType(AttackChainNode node) {
        if (node.getLabel().startsWith("⚠")) return "impact";
        if (node.getDepth() == 0) return "entry";
        return "vulnerability";
    }

    private String resolveEdgeColor(double confidence) {
        if (confidence >= 0.8) return "#FF1744";  // Red — high confidence
        if (confidence >= 0.6) return "#FF6D00";  // Orange
        if (confidence >= 0.4) return "#FFC400";  // Yellow
        return "#9E9E9E";                          // Grey — low confidence
    }

    private String formatConfidence(double confidence) {
        if (confidence >= 0.8) return "High";
        if (confidence >= 0.6) return "Medium";
        if (confidence >= 0.4) return "Low";
        return "Very Low";
    }
}

