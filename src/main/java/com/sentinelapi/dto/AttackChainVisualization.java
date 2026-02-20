package com.sentinelapi.dto;

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
public class AttackChainVisualization {

    private String targetUrl;

    private List<AttackChain> attackChains;

    private int totalChains;

    private double maxRiskScore;

    private String overallThreatLevel;

    private List<AttackChainNode> allNodes;

    private List<AttackChainEdge> allEdges;


    private Map<String, Integer> chainSeverityDistribution;


    private String topRemediation;

    private int chainsBlockedByTopRemediation;
}

