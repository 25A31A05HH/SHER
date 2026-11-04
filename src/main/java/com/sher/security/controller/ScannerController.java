
package com.sher.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class ScannerController {

    @GetMapping("/scanner")
    public String scannerPage() {
        return "scanner";
    }

    @PostMapping("/scanner")
    public String submitUrl(
            @RequestParam("url") String url,
            RedirectAttributes redirectAttributes) {

        if (url == null || url.isBlank() || url.length() > 2048) {
            redirectAttributes.addFlashAttribute(
                    "error", "Please enter a valid URL.");
            return "redirect:/scanner";
        }

        redirectAttributes.addFlashAttribute(
                "submittedUrl", url);

        return "redirect:/scanner";
    }
}
