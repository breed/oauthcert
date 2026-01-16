package com.homeofcode.wgkeyman;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(RootController.class)
@Import(SecurityConfig.class)
class RootControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private WgKeymanConfig config;

    @Test
    void testIndex_X509Disabled_RedirectsToWg() throws Exception {
        when(config.isX509Enabled()).thenReturn(false);

        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/wg/"));
    }

    @Test
    void testIndex_X509Enabled_ShowsSelectPage() throws Exception {
        when(config.isX509Enabled()).thenReturn(true);

        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("select"));
    }
}
