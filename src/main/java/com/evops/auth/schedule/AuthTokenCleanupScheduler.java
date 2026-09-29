package com.evops.auth.schedule;

import com.evops.auth.service.TokenStateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * 令牌清理调度入口：每日按 auth.jwt.cleanup-cron 触发（默认 03:30，避开 02:10 勾稽作业）。
 * 黑名单行只保留到对应令牌自身 exp，过期后令牌验签本就过不去，物理删除安全；
 * 刷新令牌台账行过期后同样无任何令牌能再引用其 jti，可物理删除。
 * 异常只记录不外抛，避免调度线程反复重试。
 */
@Component
@ConditionalOnProperty(prefix = "auth.jwt", name = "scheduling-enabled", havingValue = "true",
        matchIfMissing = true)
public class AuthTokenCleanupScheduler {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenCleanupScheduler.class);

    private final TokenStateService tokenStateService;

    public AuthTokenCleanupScheduler(TokenStateService tokenStateService) {
        this.tokenStateService = tokenStateService;
    }

    /** Quartz 每日调用：清理已到期黑名单与已到期刷新令牌台账。 */
    public void runCleanup() {
        LocalDateTime now = LocalDateTime.now();
        try {
            int blacklistDeleted = tokenStateService.cleanupExpiredBlacklist(now);
            int refreshDeleted = tokenStateService.cleanupExpiredRefreshTokens(now);
            log.info("令牌清理完成：黑名单删除 {} 行，过期刷新令牌删除 {} 行", blacklistDeleted, refreshDeleted);
        } catch (Exception e) {
            // 次日调度/手工可再跑；单表 DELETE 无跨表事务依赖
            log.error("令牌清理执行失败", e);
        }
    }
}
