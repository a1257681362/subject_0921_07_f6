package com.evops.auth.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.Version;
import com.evops.common.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDateTime;

/**
 * 刷新令牌台账行。无状态会话中服务端保留的唯一状态锚点：
 * 登录建行 ACTIVE；刷新轮换时旧行 ROTATED 并指向新行；登出/重放置 REVOKED。
 */
@Data
@EqualsAndHashCode(callSuper = true)
@TableName("t_refresh_token")
public class RefreshToken extends BaseEntity {
    private Long userId;
    private String tokenJti;
    private String sessionId;
    /** ACTIVE / ROTATED / REVOKED。 */
    private String status;
    /** 轮换后继令牌 jti（仅 ROTATED 有值）。 */
    private String rotatedToJti;
    private String revokeReason;
    private LocalDateTime expiresAt;

    @Version
    private Integer version = 0;
}
