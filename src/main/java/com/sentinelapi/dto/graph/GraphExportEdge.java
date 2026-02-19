package com.sentinelapi.dto.graph;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * React Flow-compatible graph edge.
 * Maps directly to the ReactFlow Edge type:
 * https://reactflow.dev/api-reference/types/edge
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GraphExportEdge {

    /** Unique edge identifier */
    private String id;

    /** Source node ID */
    private String source;

    /** Target node ID */
    private String target;

    /** Source handle position (for React Flow) */
    private String sourceHandle;

    /** Target handle position (for React Flow) */
    private String targetHandle;

    /** Edge type: "smoothstep", "straight", "bezier", etc. */
    private String type;

    /** Whether the edge should be animated (pulsing flow) */
    private boolean animated;

    /** Label text displayed on the edge */
    private String label;

    /** Marker at the end of the edge (arrowhead) */
    private Map<String, String> markerEnd;

    /** CSS-like style for the edge path */
    private Map<String, String> style;

    /** Label style */
    private Map<String, String> labelStyle;

    /** Additional data for custom edge rendering */
    private Map<String, Object> data;
}

