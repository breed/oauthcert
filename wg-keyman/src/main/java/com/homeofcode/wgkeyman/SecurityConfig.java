package com.homeofcode.wgkeyman;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final WgKeymanConfig config;

    public SecurityConfig(WgKeymanConfig config) {
        this.config = config;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> {
                    if (config.isX509Enabled()) {
                        authorize.requestMatchers("/x509/**").permitAll();
                    } else {
                        authorize.requestMatchers("/x509/**").denyAll();
                    }
                    authorize
                            .requestMatchers("/wg/**").authenticated()
                            .requestMatchers("/", "/error", "/favicon.ico", "/style.css").permitAll()
                            .requestMatchers("/login/**", "/oauth2/**").permitAll()
                            .anyRequest().authenticated();
                })
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/wg/", true)
                )
                .csrf(csrf -> {
                    if (config.isX509Enabled()) {
                        csrf.ignoringRequestMatchers("/x509/**");
                    }
                    csrf.ignoringRequestMatchers("/login/**", "/oauth2/**");
                });

        return http.build();
    }
}
