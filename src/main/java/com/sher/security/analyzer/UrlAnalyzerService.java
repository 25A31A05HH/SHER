
package com.sher.security.analyzer;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class UrlAnalyzerService {

    private static final Set<String> SUSPICIOUS_WORDS = Set.of(
            "login", "verify", "verification", "account",
            "password", "secure", "update", "banking",
            "signin", "confirm", "wallet", "payment"
    );

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co",
            "is.gd", "cutt.ly", "rb.gy"
    );

    public UrlAnalysisResult analyze(String input) {

        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("URL cannot be empty.");
        }

        String value = input.trim();

        if (value.length() > 2048 ||
                value.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("Invalid URL format.");
        }

        URI uri;

        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid URL format.");
        }

        String scheme = uri.getScheme();

        if (scheme == null ||
                !(scheme.equalsIgnoreCase("http") ||
                  scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException(
                    "Only HTTP and HTTPS URLs are supported.");
        }

        String host = uri.getHost();

        if (host == null || host.isBlank() ||
                uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException(
                    "URL must contain a valid hostname without embedded credentials.");
        }

        host = host.toLowerCase(Locale.ROOT);

        List<String> indicators = new ArrayList<>();
        int score = 0;

        // HTTP protocol check
        if (scheme.equalsIgnoreCase("http")) {
            score += 10;
            indicators.add(
                    "The URL uses HTTP instead of encrypted HTTPS.");
        }

        // IP address hostname check
        if (isIpAddress(host)) {
            score += 25;
            indicators.add(
                    "The hostname is an IP address instead of a domain name.");
        }

        // Punycode domain check
        if (host.contains("xn--")) {
            score += 20;
            indicators.add(
                    "The domain contains internationalized punycode labels.");
        }

        // URL length check
        if (value.length() > 100) {
            score += 10;
            indicators.add(
                    "The URL is unusually long.");
        }

        // Subdomain check
        long subdomains = host.chars()
                .filter(character -> character == '.')
                .count();

        if (subdomains >= 4) {
            score += 15;
            indicators.add(
                    "The hostname contains many domain labels.");
        }

        // Suspicious keyword check
        String lowerUrl = value.toLowerCase(Locale.ROOT);

        for (String word : SUSPICIOUS_WORDS) {
            if (lowerUrl.contains(word)) {
                score += 8;
                indicators.add(
                        "Suspicious keyword detected: " + word);
            }
        }

        // URL shortener check
        if (SHORTENERS.contains(host)) {
            score += 20;
            indicators.add(
                    "The URL uses a known URL-shortening domain.");
        }

        // Unusual port check
        int port = uri.getPort();

        if (port != -1 && port != 80 && port != 443) {
            score += 10;
            indicators.add(
                    "The URL uses a non-standard network port.");
        }

        // Query string check
        String query = uri.getRawQuery();

        if (query != null && query.length() > 150) {
            score += 10;
            indicators.add(
                    "The URL contains an unusually long query string.");
        }

        score = Math.min(score, 100);

        String classification;
        String recommendation;

        if (score >= 70) {
            classification = "High apparent risk";
            recommendation =
                    "Avoid interacting with this URL until it has been independently verified.";
        } else if (score >= 30) {
            classification = "Suspicious";
            recommendation =
                    "Verify the domain through a trusted source before proceeding.";
        } else {
            classification = "Low apparent risk";
            recommendation =
                    "No strong warning patterns were detected by the current heuristic checks. This does not guarantee safety.";
        }

        if (indicators.isEmpty()) {
            indicators.add(
                    "No configured suspicious URL patterns were detected.");
        }

        return new UrlAnalysisResult(
                value,
                score,
                classification,
                List.copyOf(indicators),
                recommendation
        );
    }

    private boolean isIpAddress(String host) {

        // IPv6 literal
        if (host.startsWith("[") && host.endsWith("]")) {
            return true;
        }

        // Basic IPv4 literal detection
        return host.matches(
                "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    }
}
