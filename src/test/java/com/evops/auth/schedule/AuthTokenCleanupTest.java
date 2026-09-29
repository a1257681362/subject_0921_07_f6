package com.evops.auth.schedule;

import com.evops.auth.TokenStatus;
import com.evops.auth.entity.RefreshToken;
import com.evops.auth.entity.TokenBlacklist;
import com.evops.auth.jwt.TokenType;
import com.evops.auth.mapper.RefreshTokenMapper;
import com.evops.auth.mapper.TokenBlacklistMapper;
import com.evops.auth.service.TokenStateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 黑名单/刷新令牌台账到期自动清理：过期行物理删除、未过期行保留；
 * 调度入口直接调用可正常执行（测试环境关闭 Quartz 注册）。
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthTokenCleanupTest {

    @Autowired
    private TokenStateService tokenStateService;
    @Autowired
    private TokenBlacklistMapper blacklistMapper;
    @Autowired
    private RefreshTokenMapper refreshTokenMapper;

    private AuthTokenCleanupScheduler scheduler;

    @BeforeEach
    void setUp() {
        // test profile 关闭了调度 Bean 注册，这里手工装配等价实例验证入口逻辑
        scheduler = new AuthTokenCleanupScheduler(tokenStateService);
    }

    private String uniqueJti(String prefix) {
        return prefix + System.nanoTime();
    }

    @Test
    void cleanup_deletesOnlyExpiredBlacklistRows() {
        String expiredJti = uniqueJti("bl-exp-");
        String aliveJti = uniqueJti("bl-alive-");

        TokenBlacklist expired = new TokenBlacklist();
        expired.setJti(expiredJti);
        expired.setTokenType(TokenType.ACCESS.name());
        expired.setReason("LOGOUT");
        expired.setExpireTime(LocalDateTime.now().minusMinutes(1));
        blacklistMapper.insert(expired);

        TokenBlacklist alive = new TokenBlacklist();
        alive.setJti(aliveJti);
        alive.setTokenType(TokenType.ACCESS.name());
        alive.setReason("LOGOUT");
        alive.setExpireTime(LocalDateTime.now().plusMinutes(10));
        blacklistMapper.insert(alive);

        assertTrue(tokenStateService.isBlacklisted(expiredJti));
        int deleted = tokenStateService.cleanupExpiredBlacklist(LocalDateTime.now());
        assertTrue(deleted >= 1);
        assertFalse(tokenStateService.isBlacklisted(expiredJti));
        assertTrue(tokenStateService.isBlacklisted(aliveJti));
    }

    @Test
    void cleanup_deletesOnlyExpiredRefreshTokenRows() {
        String expiredJti = uniqueJti("rt-exp-");
        String aliveJti = uniqueJti("rt-alive-");

        RefreshToken expired = new RefreshToken();
        expired.setUserId(999L);
        expired.setTokenJti(expiredJti);
        expired.setSessionId("sid-cleanup-1");
        expired.setStatus(TokenStatus.ROTATED);
        expired.setExpiresAt(LocalDateTime.now().minusDays(1));
        refreshTokenMapper.insert(expired);

        RefreshToken alive = new RefreshToken();
        alive.setUserId(999L);
        alive.setTokenJti(aliveJti);
        alive.setSessionId("sid-cleanup-2");
        alive.setStatus(TokenStatus.ACTIVE);
        alive.setExpiresAt(LocalDateTime.now().plusDays(1));
        refreshTokenMapper.insert(alive);

        int deleted = tokenStateService.cleanupExpiredRefreshTokens(LocalDateTime.now());
        assertTrue(deleted >= 1);
        assertEquals(0, refreshTokenMapper.selectCount(
                new com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper<RefreshToken>()
                        .eq(RefreshToken::getTokenJti, expiredJti)));
        assertEquals(1, refreshTokenMapper.selectCount(
                new com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper<RefreshToken>()
                        .eq(RefreshToken::getTokenJti, aliveJti)));
    }

    @Test
    void scheduler_runCleanup_executesWithoutError() {
        // 等价于 Quartz 每日触发；不抛异常即通过
        scheduler.runCleanup();
    }
}
