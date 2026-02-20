package com.sentinelapi.dto.graph;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GraphExportEdge {

    private String id;

    private String source;

    private String target;

    private String sourceHandle;

    private String targetHandle;

    private String type;

    private boolean animated;

    private String label;

    private Map<String, String> markerEnd;

    private Map<String, String> style;

    private Map<String, String> labelStyle;

    private Map<String, Object> data;
}

