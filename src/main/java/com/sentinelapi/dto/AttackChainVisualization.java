package com.sentinelapi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * The complete attack chain visualization payload.
 * Contains all discovered chains plus graph metadata for rendering.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChainVisualization {

    /** Target that was scanned */
    private String targetUrl;

    /** All discovered attack chains, ordered by risk score descending */
    private List<AttackChain> attackChains;

    /** Total number of chains discovered */
    private int totalChains;

    /** Highest risk score across all chains */
    private double maxRiskScore;

    /** Overall threat level label */
    private String overallThreatLevel;

    /**
     * Combined flat graph of ALL nodes across all chains.
     * Useful for rendering a single unified attack graph.
     */
    private List<AttackChainNode> allNodes;

    /**
     * Combined flat list of ALL edges across all chains.
     */
    private List<AttackChainEdge> allEdges;

    /**
     * Summary: how many chains at each threat tier.
     * e.g., {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1}
     */
    private Map<String, Integer> chainSeverityDistribution;

    /**
     * The single most impactful remediation action that would
     * break the most attack chains simultaneously.
     */
    private String topRemediation;

    /** Number of chains that topRemediation would break */
    private int chainsBlockedByTopRemediation;
}

