
package com.sher.security.analyzer;

import java.util.List;

public record UrlAnalysisResult(
        String analyzedUrl,
        int riskScore,
        String classification,
        List<String> indicators,
        String recommendation
) {
}
