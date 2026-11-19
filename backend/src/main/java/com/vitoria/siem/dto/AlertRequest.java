package com.vitoria.siem.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import tools.jackson.databind.JsonNode;

import java.time.Instant;

public record AlertRequest(
        @NotBlank String source,
        @NotNull Instant timestamp,
        @NotBlank String srcIp,
        @NotBlank String eventType,
        @NotBlank String severity,
        JsonNode details
) {}
