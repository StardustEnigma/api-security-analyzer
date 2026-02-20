package com.sentinelapi.dto;

import com.sentinelapi.model.Severity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChain {

    private String id;

    private String title;

    private String description;

    private List<AttackChainNode> nodes;

    private List<AttackChainEdge> edges;

    private Severity maxSeverity;

    private double riskScore;

    private int chainLength;

    private String impact;

    private String priorityRemediation;
}

