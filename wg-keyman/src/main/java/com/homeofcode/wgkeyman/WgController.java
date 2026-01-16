package com.homeofcode.wgkeyman;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.nio.charset.StandardCharsets;

@Controller
@RequestMapping("/wg")
public class WgController {

    private final CertificateService certificateService;

    public WgController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal OAuth2User principal, Model model) {
        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        model.addAttribute("email", email);
        model.addAttribute("name", name);

        if (!certificateService.isAuthorizedUser(email)) {
            return "wg-unauthorized";
        }

        return "wg-upload";
    }

    @PostMapping("/submit")
    public String submitPublicKey(@AuthenticationPrincipal OAuth2User principal,
                                   @RequestParam("publicKey") String publicKey,
                                   Model model) {
        String email = principal.getAttribute("email");

        CertificateService.CertificateResult result = certificateService.processPublicKey(email, publicKey);

        if (!result.valid()) {
            model.addAttribute("error", result.errorMessage());
            model.addAttribute("email", email);
            model.addAttribute("name", principal.getAttribute("name"));
            model.addAttribute("publicKey", publicKey);
            return "wg-upload";
        }

        model.addAttribute("commonName", result.commonName());
        model.addAttribute("wireguardPublicKey", result.wireguardPublicKey());
        model.addAttribute("wireguardConfig", result.wireguardConfig());
        model.addAttribute("warning", result.warningMessage());
        return "wg-result";
    }

    @PostMapping("/download")
    public ResponseEntity<byte[]> downloadConfig(@RequestParam("config") String config,
                                                  @RequestParam("cn") String cn) {
        String filename = cn.replace("@", "_at_") + ".conf";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.TEXT_PLAIN)
                .body(config.getBytes(StandardCharsets.UTF_8));
    }
}
