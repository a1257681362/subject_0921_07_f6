package com.evops.auth.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.evops.auth.RevokeReason;
import com.evops.auth.TokenStatus;
import com.evops.auth.entity.RefreshToken;
import com.evops.auth.entity.TokenBlacklist;
import com.evops.auth.jwt.JwtProperties;
import com.evops.auth.jwt.TokenType;
import com.evops.auth.mapper.RefreshTokenMapper;
import com.evops.auth.mapper.TokenBlacklistMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * 令牌状态校验：黑名单（按 jti）+ 会话级连坐标记（按 sessionId）。
 * 过滤链每请求查一次，均走索引。行的 expire_time 取令牌自身 exp，到期后由清理任务物理删除。
 */
@Service
public class TokenStateService {

    private static final Logger log = LoggerFactory.getLogger(TokenStateService.class);

    private final TokenBlacklistMapper blacklistMapper;
    private final RefreshTokenMapper refreshTokenMapper;
    private final JwtProperties properties;

    public TokenStateService(TokenBlacklistMapper blacklistMapper,
                             RefreshTokenMapper refreshTokenMapper,
                             JwtProperties properties) {
        this.blacklistMapper = blacklistMapper;
        this.refreshTokenMapper = refreshTokenMapper;
        this.properties = properties;
    }

    /** jti 是否在黑名单（登出/重放出现过的令牌）。 */
    public boolean isBlacklisted(String jti) {
        Long count = blacklistMapper.selectCount(new LambdaQueryWrapper<TokenBlacklist>()
                .eq(TokenBlacklist::getJti, jti));
        return count != null && count > 0;
    }

    /**
     * 会话是否已被连坐吊销：重放检出或改密时，该会话刷新令牌被置 REVOKED 并带会话级原因。
     * 访问令牌本身无状态、jti 未登记，因此靠该会话级标记让仍在有效期内的访问令牌一并立即失效。
     */
    public boolean isSessionCompromised(String sessionId) {
        Long count = refreshTokenMapper.selectCount(new LambdaQueryWrapper<RefreshToken>()
                .eq(RefreshToken::getSessionId, sessionId)
                .eq(RefreshToken::getStatus, TokenStatus.REVOKED)
                .in(RefreshToken::getRevokeReason, java.util.Arrays.asList(RevokeReason.SESSION_LEVEL_REASONS)));
        return count != null && count > 0;
    }

    /** 登记黑名单；同一 jti 并发登记只留一行（唯一约束兜底，重复忽略）。 */
    public void blacklist(String jti, TokenType type, String reason, Long userId, long expiresAtEpochSecond) {
        TokenBlacklist row = new TokenBlacklist();
        row.setJti(jti);
        row.setTokenType(type.name());
        row.setReason(reason);
        row.setUserId(userId);
        // 保留到 exp + 时钟偏移容忍：避免行在 exp 被清理后、容忍窗口内令牌仍能通过验签
        long retainUntil = expiresAtEpochSecond + properties.getClockSkewSeconds() + 1;
        row.setExpireTime(LocalDateTime.ofInstant(
                Instant.ofEpochSecond(retainUntil), ZoneId.systemDefault()));
        row.setCreateBy(userId);
        try {
            blacklistMapper.insert(row);
        } catch (DuplicateKeyException e) {
            // 已在黑名单（并发登出等），幂等忽略
            log.debug("jti {} 已在黑名单，忽略重复登记", jti);
        }
    }

    /**
     * 重放/改密的会话级连坐吊销，独立事务立即提交（REQUIRES_NEW）：
     * 调用方检测到重放后会抛业务异常导致外层事务回滚，吊销必须先落库，否则连坐失效。
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeSessionInNewTx(String sessionId, String jti, Long userId,
                                     long expiresAtEpochSecond, String reason) {
        refreshTokenMapper.update(null, new LambdaUpdateWrapper<RefreshToken>()
                .eq(RefreshToken::getSessionId, sessionId)
                .eq(RefreshToken::getStatus, TokenStatus.ACTIVE)
                .set(RefreshToken::getStatus, TokenStatus.REVOKED)
                .set(RefreshToken::getRevokeReason, reason));
        blacklist(jti, TokenType.REFRESH, reason, userId, expiresAtEpochSecond);
    }

    /** 物理清理：删除已到期黑名单行，返回删除条数。 */
    public int cleanupExpiredBlacklist(LocalDateTime now) {
        return blacklistMapper.delete(new LambdaQueryWrapper<TokenBlacklist>()
                .lt(TokenBlacklist::getExpireTime, now));
    }

    /** 物理清理：删除已到期的刷新令牌台账行（无论终态），额外留一个时钟偏移容忍窗口。 */
    public int cleanupExpiredRefreshTokens(LocalDateTime now) {
        LocalDateTime threshold = now.minusSeconds(properties.getClockSkewSeconds() + 1);
        return refreshTokenMapper.delete(new LambdaQueryWrapper<RefreshToken>()
                .lt(RefreshToken::getExpiresAt, threshold));
    }
}
