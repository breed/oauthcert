package com.homeofcode.wgkeyman;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;

@Controller
@RequestMapping("/x509")
public class WgKeymanController {

    private final CertificateService certificateService;

    public WgKeymanController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @GetMapping("/")
    public String index() {
        return "upload";
    }

    @PostMapping("/upload")
    public String uploadCertificate(@RequestParam("certificate") MultipartFile file, Model model) {
        if (file.isEmpty()) {
            model.addAttribute("error", "Please select a certificate file to upload");
            return "upload";
        }

        try {
            String pemContent = new String(file.getBytes(), StandardCharsets.UTF_8);
            CertificateService.CertificateResult result = certificateService.processCertificate(pemContent);

            if (!result.valid()) {
                model.addAttribute("error", result.errorMessage());
                return "upload";
            }

            model.addAttribute("commonName", result.commonName());
            model.addAttribute("wireguardPublicKey", result.wireguardPublicKey());
            model.addAttribute("wireguardConfig", result.wireguardConfig());
            model.addAttribute("warning", result.warningMessage());
            return "result";

        } catch (Exception e) {
            model.addAttribute("error", "Error reading certificate file: " + e.getMessage());
            return "upload";
        }
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
