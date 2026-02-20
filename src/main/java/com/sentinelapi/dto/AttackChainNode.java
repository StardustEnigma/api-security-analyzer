package com.sentinelapi.dto;

import com.sentinelapi.model.Severity;
import com.sentinelapi.model.VulnerabilityCategory;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChainNode {

    private String id;

    private String label;

    private String vulnerabilityName;

    private VulnerabilityCategory category;

    private Severity severity;


    private String attackerAction;

    private String outcome;

    private int depth;
}

