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
public class GraphExportNode {

    private String id;

    private String type;

    private Position position;

    private Map<String, Object> data;

    private Map<String, String> style;

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

