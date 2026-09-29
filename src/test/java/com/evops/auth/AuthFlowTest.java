package com.evops.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 无状态会话全链路：登录、无令牌 401、刷新轮换一次性、旧令牌重放吊销整会话、
 * 登出黑名单、篡改/类型错误令牌拒绝、/me、改密即失效。
 * 本类显式打开过滤链；存量接口测试仍走 test profile 的关闭口径。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "auth.jwt.filter-enabled=true")
class AuthFlowTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private static String loginBody(String username, String password) {
        return "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    }

    private String login(String username, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(username, password)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andReturn().getResponse().getContentAsString();
    }

    private JsonNode loginPair(String username, String password) throws Exception {
        return JSON.readTree(login(username, password)).path("data");
    }

    private JsonNode refresh(String refreshToken) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andReturn();
        return JSON.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private MvcResult refreshRaw(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refreshToken + "\"}")).andReturn();
    }

    @Test
    void login_wrongPassword_fail() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("admin", "wrong-pass")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("用户名或密码不正确"));
    }

    @Test
    void login_unknownUser_sameErrorMessage() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("nobody", "whatever1")))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("用户名或密码不正确"));
    }

    @Test
    void protectedApi_withoutToken_401() throws Exception {
        mockMvc.perform(get("/api/machines"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void loginThenCallProtectedApi_ok() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        mockMvc.perform(get("/api/machines")
                        .header("Authorization", "Bearer " + pair.path("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void me_returnsCurrentUser_andTokenHasNoUsername() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        // 令牌载荷里不含用户名等敏感明文
        String[] parts = pair.path("accessToken").asText().split("\\.");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        org.junit.jupiter.api.Assertions.assertFalse(payload.contains("admin"));

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + pair.path("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("admin"))
                .andExpect(jsonPath("$.data.displayName").value("系统管理员"));
    }

    @Test
    void refresh_rotatesAndOldTokenOneTimeOnly() throws Exception {
        JsonNode first = loginPair("admin", "admin123");
        String oldAccess = first.path("accessToken").asText();
        String oldRefresh = first.path("refreshToken").asText();

        // 第一次刷新成功，下发全新双令牌
        JsonNode second = refresh(oldRefresh);
        org.junit.jupiter.api.Assertions.assertNotEquals(oldRefresh, second.path("refreshToken").asText());
        org.junit.jupiter.api.Assertions.assertNotEquals(oldAccess, second.path("accessToken").asText());

        // 新访问令牌可用
        mockMvc.perform(get("/api/machines")
                        .header("Authorization", "Bearer " + second.path("accessToken").asText()))
                .andExpect(status().isOk());

        // 旧刷新令牌再用 = 重放：拒绝并吊销整会话
        MvcResult replay = refreshRaw(oldRefresh);
        org.junit.jupiter.api.Assertions.assertEquals(200, replay.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertTrue(
                JSON.readTree(replay.getResponse().getContentAsString()).path("message").asText()
                        .contains("已全部失效"));

        // 连坐：轮换后尚在有效期的新访问令牌立即失效
        mockMvc.perform(get("/api/machines")
                        .header("Authorization", "Bearer " + second.path("accessToken").asText()))
                .andExpect(status().isUnauthorized());

        // 连坐：最新一张刷新令牌同样不能再换新（会话已整体吊销）
        MvcResult latest = refreshRaw(second.path("refreshToken").asText());
        org.junit.jupiter.api.Assertions.assertFalse(
                JSON.readTree(latest.getResponse().getContentAsString()).path("success").asBoolean());
    }

    @Test
    void refresh_withAccessTypeToken_rejected() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + pair.path("accessToken").asText() + "\"}"))
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void businessApi_withRefreshTypeToken_401() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        mockMvc.perform(get("/api/machines")
                        .header("Authorization", "Bearer " + pair.path("refreshToken").asText()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_blacklistsAccessToken() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        String access = pair.path("accessToken").asText();

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + pair.path("refreshToken").asText() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // 同一访问令牌再次使用即被黑名单拦
        mockMvc.perform(get("/api/machines").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_withoutRefreshToken_stillBlacklistsAccess() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        String access = pair.path("accessToken").asText();
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/machines").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedToken_401() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        String token = pair.path("accessToken").asText();
        char last = token.charAt(token.length() - 1);
        String tampered = token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
        mockMvc.perform(get("/api/machines").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/machines").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_revokesAllSessionsAndOldPasswordRejected() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        String access = pair.path("accessToken").asText();

        mockMvc.perform(post("/api/auth/change-password")
                        .header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"oldPassword\":\"admin123\",\"newPassword\":\"admin456789\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        // 旧访问令牌立即失效
        mockMvc.perform(get("/api/machines").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
        // 旧口令登不上，新口令可以
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("admin", "admin123")))
                .andExpect(jsonPath("$.success").value(false));
        JsonNode newPair = loginPair("admin", "admin456789");
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + newPair.path("accessToken").asText()))
                .andExpect(status().isOk());

        // 还原种子口令，避免影响同库其他用例
        mockMvc.perform(post("/api/auth/change-password")
                        .header("Authorization", "Bearer " + newPair.path("accessToken").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"oldPassword\":\"admin456789\",\"newPassword\":\"admin123\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void changePassword_wrongOldPassword_fail() throws Exception {
        JsonNode pair = loginPair("admin", "admin123");
        mockMvc.perform(post("/api/auth/change-password")
                        .header("Authorization", "Bearer " + pair.path("accessToken").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"oldPassword\":\"bad-old\",\"newPassword\":\"newpass123\"}"))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("原密码不正确"));
    }
}
