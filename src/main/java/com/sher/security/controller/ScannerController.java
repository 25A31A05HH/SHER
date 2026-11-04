package com.sher.security.controller;

import com.sher.security.analyzer.UrlAnalysisResult;
import com.sher.security.analyzer.UrlAnalyzerService;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ScannerController {

    private final UrlAnalyzerService urlAnalyzerService;

    public ScannerController(UrlAnalyzerService urlAnalyzerService) {
        this.urlAnalyzerService = urlAnalyzerService;
    }

    @GetMapping("/scanner")
    public String scannerPage() {
        return "scanner";
    }

    @PostMapping("/scanner")
    public String submitUrl(
            @RequestParam("url") String url,
            Model model) {

        try {
            UrlAnalysisResult result = urlAnalyzerService.analyze(url);
            model.addAttribute("analysis", result);

        } catch (IllegalArgumentException exception) {
            model.addAttribute("error", exception.getMessage());
        }

        model.addAttribute("submittedUrl", url);

        return "scanner";
    }
}
