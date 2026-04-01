package com.example.vulnerable;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class VulnerableApplicationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void searchEndpointIsReachable() throws Exception {
        mockMvc.perform(get("/search/users?name=alice"))
               .andExpect(status().isOk());
    }

    @Test
    void pingEndpointIsReachable() throws Exception {
        mockMvc.perform(get("/system/ping?host=localhost"))
               .andExpect(status().isOk());
    }

    @Test
    void getAllUsersEndpointIsReachable() throws Exception {
        mockMvc.perform(get("/users/all"))
               .andExpect(status().isOk());
    }
}
