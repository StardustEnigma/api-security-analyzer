package com.sentinelapi.dto;

import com.sentinelapi.model.Severity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * A complete attack chain — an ordered sequence of exploit steps
 * that an attacker could use to escalate from an initial weakness
 * to a high-impact outcome.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChain {

    /** Unique chain identifier (e.g., "chain-1") */
    private String id;

    /** Short title describing the overall attack scenario */
    private String title;

    /** Narrative description of the full attack flow */
    private String description;

    /** Ordered nodes forming this chain */
    private List<AttackChainNode> nodes;

    /** Edges connecting the nodes */
    private List<AttackChainEdge> edges;

    /** The highest severity reached at any step in this chain */
    private Severity maxSeverity;

    /**
     * Composite risk score (0-100) that considers:
     * - individual vuln severities
     * - number of steps (fewer = easier to exploit)
     * - chain confidence
     */
    private double riskScore;

    /** Number of steps in this chain */
    private int chainLength;

    /** The ultimate impact if the full chain is exploited */
    private String impact;

    /** Priority remediation — the single fix that breaks this chain most effectively */
    private String priorityRemediation;
}

