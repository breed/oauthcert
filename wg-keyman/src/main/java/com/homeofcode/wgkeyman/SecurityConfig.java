package com.homeofcode.wgkeyman;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // Allow public access to /x509 endpoints (certificate-based auth)
                        .requestMatchers("/x509/**").permitAll()
                        // Require OAuth2 login for /wg endpoints
                        .requestMatchers("/wg/**").authenticated()
                        // Allow public access to static resources and root
                        .requestMatchers("/", "/error", "/favicon.ico", "/style.css").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/wg/", true)
                )
                .csrf(csrf -> csrf
                        // Disable CSRF for /x509 endpoints (they use certificate auth)
                        .ignoringRequestMatchers("/x509/**")
                );

        return http.build();
    }
}
