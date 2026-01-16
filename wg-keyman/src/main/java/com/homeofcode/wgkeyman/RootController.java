package com.homeofcode.wgkeyman;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RootController {

    private final WgKeymanConfig config;

    public RootController(WgKeymanConfig config) {
        this.config = config;
    }

    @GetMapping("/")
    public String index() {
        if (config.isX509Enabled()) {
            return "select";
        }
        return "redirect:/wg/";
    }
}
