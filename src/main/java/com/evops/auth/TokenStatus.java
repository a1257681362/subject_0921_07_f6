package com.evops.auth;

/** 刷新令牌台账状态。 */
public final class TokenStatus {
    /** 当前有效（每会话同时只有一行 ACTIVE）。 */
    public static final String ACTIVE = "ACTIVE";
    /** 已被刷新轮换，rotated_to_jti 指向后继；该行不可再次使用。 */
    public static final String ROTATED = "ROTATED";
    /** 已吊销（登出/重放检出/管理员处置）。 */
    public static final String REVOKED = "REVOKED";

    private TokenStatus() {
    }
}
