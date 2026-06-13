package com.homeofcode.wgkeyman;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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

    private final WireguardService wireguardService;

    public WgController(WireguardService wireguardService) {
        this.wireguardService = wireguardService;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal OAuth2User principal, Model model) {
        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        model.addAttribute("email", email);
        model.addAttribute("name", name);

        if (!isEmailVerified(principal) || !wireguardService.isAuthorizedUser(email)) {
            return "wg-unauthorized";
        }

        return "wg-upload";
    }

    @PostMapping("/submit")
    public String submitPublicKey(@AuthenticationPrincipal OAuth2User principal,
                                   @RequestParam("publicKey") String publicKey,
                                   Model model) {
        String email = principal.getAttribute("email");

        if (!isEmailVerified(principal)) {
            model.addAttribute("email", email);
            model.addAttribute("name", principal.getAttribute("name"));
            return "wg-unauthorized";
        }

        WireguardService.WireguardResult result = wireguardService.processPublicKey(email, publicKey);

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

    /**
     * Re-generate and download the authenticated user's config. The config and filename are derived
     * server-side from the authenticated principal and the user's registered key — nothing from the
     * request body is echoed back (avoids reflected-file-download and Content-Disposition injection).
     */
    @PostMapping("/download")
    public ResponseEntity<byte[]> downloadConfig(@AuthenticationPrincipal OAuth2User principal) {
        String email = principal.getAttribute("email");
        if (email == null || !isEmailVerified(principal) || !wireguardService.isAuthorizedUser(email)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        String publicKey = wireguardService.getPeerPublicKey(email);
        if (publicKey == null) {
            // No key registered yet — nothing to download.
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        String config = wireguardService.generateWireguardConfig(email, publicKey);
        String filename = email.replaceAll("[^A-Za-z0-9._-]", "_") + ".conf";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.TEXT_PLAIN)
                .body(config.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Whether the OAuth provider asserts the user's email is verified. If the provider supplies the
     * {@code email_verified} claim it must be true; if the claim is absent we don't block (not all
     * providers emit it).
     */
    private boolean isEmailVerified(OAuth2User principal) {
        Object verified = principal.getAttribute("email_verified");
        return verified == null || Boolean.parseBoolean(String.valueOf(verified));
    }
}
