package com.homeofcode.wgkeyman;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(WgController.class)
@Import(SecurityConfig.class)
class WgControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private WireguardService wireguardService;

    @MockBean
    private WgKeymanConfig wgKeymanConfig;

    private OAuth2User createOAuth2User(String email, String name) {
        Map<String, Object> attributes = Map.of(
                "email", email,
                "name", name,
                "sub", "12345"
        );
        return new DefaultOAuth2User(
                Collections.emptyList(),
                attributes,
                "sub"
        );
    }

    @Test
    void testIndex_AuthorizedUser_ReturnsUploadPage() throws Exception {
        when(wireguardService.isAuthorizedUser("test@example.com")).thenReturn(true);

        mockMvc.perform(get("/wg/")
                        .with(oauth2Login().oauth2User(createOAuth2User("test@example.com", "Test User"))))
                .andExpect(status().isOk())
                .andExpect(view().name("wg-upload"))
                .andExpect(model().attribute("email", "test@example.com"))
                .andExpect(model().attribute("name", "Test User"));
    }

    @Test
    void testIndex_UnauthorizedUser_ReturnsUnauthorizedPage() throws Exception {
        when(wireguardService.isAuthorizedUser("unknown@example.com")).thenReturn(false);

        mockMvc.perform(get("/wg/")
                        .with(oauth2Login().oauth2User(createOAuth2User("unknown@example.com", "Unknown User"))))
                .andExpect(status().isOk())
                .andExpect(view().name("wg-unauthorized"))
                .andExpect(model().attribute("email", "unknown@example.com"))
                .andExpect(model().attribute("name", "Unknown User"));
    }

    @Test
    void testIndex_Unauthenticated_RedirectsToLogin() throws Exception {
        mockMvc.perform(get("/wg/"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void testSubmitPublicKey_Success() throws Exception {
        String email = "test@example.com";
        String publicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        String config = "[Interface]\nAddress = 10.0.0.5/32\n";

        when(wireguardService.processPublicKey(email, publicKey))
                .thenReturn(WireguardService.WireguardResult.success(email, publicKey, config));

        mockMvc.perform(post("/wg/submit")
                        .with(oauth2Login().oauth2User(createOAuth2User(email, "Test User")))
                        .with(csrf())
                        .param("publicKey", publicKey))
                .andExpect(status().isOk())
                .andExpect(view().name("wg-result"))
                .andExpect(model().attribute("commonName", email))
                .andExpect(model().attribute("wireguardPublicKey", publicKey))
                .andExpect(model().attribute("wireguardConfig", config));
    }

    @Test
    void testSubmitPublicKey_UnauthorizedUser() throws Exception {
        String email = "unauthorized@example.com";
        String publicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";

        when(wireguardService.processPublicKey(email, publicKey))
                .thenReturn(WireguardService.WireguardResult.error("User 'unauthorized@example.com' is not authorized"));

        mockMvc.perform(post("/wg/submit")
                        .with(oauth2Login().oauth2User(createOAuth2User(email, "Unauthorized User")))
                        .with(csrf())
                        .param("publicKey", publicKey))
                .andExpect(status().isOk())
                .andExpect(view().name("wg-upload"))
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attribute("email", email));
    }

    @Test
    void testSubmitPublicKey_InvalidPublicKey() throws Exception {
        String email = "test@example.com";
        String invalidKey = "invalid";

        when(wireguardService.processPublicKey(email, invalidKey))
                .thenReturn(WireguardService.WireguardResult.error("Invalid WireGuard public key format"));

        mockMvc.perform(post("/wg/submit")
                        .with(oauth2Login().oauth2User(createOAuth2User(email, "Test User")))
                        .with(csrf())
                        .param("publicKey", invalidKey))
                .andExpect(status().isOk())
                .andExpect(view().name("wg-upload"))
                .andExpect(model().attributeExists("error"))
                .andExpect(model().attribute("publicKey", invalidKey));
    }

    @Test
    void testSubmitPublicKey_Unauthenticated_RedirectsToLogin() throws Exception {
        mockMvc.perform(post("/wg/submit")
                        .with(csrf())
                        .param("publicKey", "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14="))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void testSubmitPublicKey_NoCsrf_Forbidden() throws Exception {
        mockMvc.perform(post("/wg/submit")
                        .with(oauth2Login().oauth2User(createOAuth2User("test@example.com", "Test User")))
                        .param("publicKey", "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14="))
                .andExpect(status().isForbidden());
    }

    @Test
    void testDownload_RegeneratesConfigServerSide() throws Exception {
        String cn = "test@example.com";
        String publicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        String config = "[Interface]\nAddress = 10.0.0.5/32\n";

        when(wireguardService.isAuthorizedUser(cn)).thenReturn(true);
        when(wireguardService.getPeerPublicKey(cn)).thenReturn(publicKey);
        when(wireguardService.generateWireguardConfig(cn, publicKey)).thenReturn(config);

        mockMvc.perform(post("/wg/download")
                        .with(oauth2Login().oauth2User(createOAuth2User(cn, "Test User")))
                        .with(csrf()))
                .andExpect(status().isOk())
                // filename is derived from the principal and sanitized (no raw '@', no quotes)
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"test_example.com.conf\""))
                .andExpect(content().contentType("text/plain"))
                .andExpect(content().string(config));
    }

    @Test
    void testDownload_NoRegisteredKey_ReturnsNotFound() throws Exception {
        String cn = "test@example.com";
        when(wireguardService.isAuthorizedUser(cn)).thenReturn(true);
        when(wireguardService.getPeerPublicKey(cn)).thenReturn(null);

        mockMvc.perform(post("/wg/download")
                        .with(oauth2Login().oauth2User(createOAuth2User(cn, "Test User")))
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    void testDownload_UnauthorizedUser_Forbidden() throws Exception {
        String cn = "unknown@example.com";
        when(wireguardService.isAuthorizedUser(cn)).thenReturn(false);

        mockMvc.perform(post("/wg/download")
                        .with(oauth2Login().oauth2User(createOAuth2User(cn, "Unknown")))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    void testDownload_Unauthenticated_RedirectsToLogin() throws Exception {
        mockMvc.perform(post("/wg/download")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void testIndex_UnverifiedEmail_ReturnsUnauthorized() throws Exception {
        // An unverified email is rejected before authorization is even checked.
        mockMvc.perform(get("/wg/")
                        .with(oauth2Login().oauth2User(createOAuth2UserUnverified("test@example.com", "Test User"))))
                .andExpect(status().isOk())
                .andExpect(view().name("wg-unauthorized"));
    }

    private OAuth2User createOAuth2UserUnverified(String email, String name) {
        Map<String, Object> attributes = Map.of(
                "email", email,
                "name", name,
                "email_verified", false,
                "sub", "12345"
        );
        return new DefaultOAuth2User(Collections.emptyList(), attributes, "sub");
    }
}
