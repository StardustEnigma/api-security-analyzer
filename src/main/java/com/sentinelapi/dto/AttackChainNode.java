package com.sentinelapi.dto;

import com.sentinelapi.model.Severity;
import com.sentinelapi.model.VulnerabilityCategory;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A single node (step) in an attack chain graph.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChainNode {

    /** Unique ID for this node within the graph (e.g., "node-1") */
    private String id;

    /** Human-readable label for this step */
    private String label;

    /** The vulnerability that enables this step */
    private String vulnerabilityName;

    /** Category of the vulnerability */
    private VulnerabilityCategory category;

    /** Severity of this particular step */
    private Severity severity;

    /** Explanation of what the attacker does at this step */
    private String attackerAction;

    /** What the attacker gains from this step */
    private String outcome;

    /**
     * Position hint for visualization layout.
     * 0 = entry point, higher = deeper in the chain.
     */
    private int depth;
}

