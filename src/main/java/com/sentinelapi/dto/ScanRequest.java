package com.sentinelapi.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScanRequest {

    @NotBlank(message = "Target URL must not be blank")
    @Pattern(
            regexp = "^https?://.*",
            message = "Target URL must start with http:// or https://"
    )
    private String targetUrl;
}

