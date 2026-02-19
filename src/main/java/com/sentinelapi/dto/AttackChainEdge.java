package com.sentinelapi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A directed edge in the attack chain graph connecting two nodes.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChainEdge {

    /** Source node ID */
    private String from;

    /** Target node ID */
    private String to;

    /** Label describing how this step leads to the next */
    private String label;

    /** Detailed explanation of the transition */
    private String description;

    /** Probability/confidence that this chain link is exploitable (0.0 - 1.0) */
    private double confidence;
}

