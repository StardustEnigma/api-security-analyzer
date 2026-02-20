package com.sentinelapi.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackChainEdge {

    private String from;

    private String to;

    private String label;

    private String description;

    private double confidence;
}

