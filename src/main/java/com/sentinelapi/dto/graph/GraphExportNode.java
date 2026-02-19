package com.sentinelapi.dto.graph;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * React Flow-compatible graph node.
 * Maps directly to the ReactFlow Node type:
 * https://reactflow.dev/api-reference/types/node
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GraphExportNode {

    /** Unique node identifier (matches attack chain node ID) */
    private String id;

    /** Node type for React Flow custom node rendering */
    private String type;

    /** Position coordinates for layout */
    private Position position;

    /**
     * Data payload rendered inside the node component.
     * Contains all fields the React frontend needs for display.
     */
    private Map<String, Object> data;

    /** CSS-like style map for the node container */
    private Map<String, String> style;

    /** Which group/chain this node belongs to (for subgraph coloring) */
    private String parentId;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Position {
        private double x;
        private double y;
    }
}

