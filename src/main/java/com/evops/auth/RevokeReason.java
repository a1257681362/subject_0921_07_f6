package com.evops.auth;

/** 吊销原因，落 t_refresh_token.revoke_reason / t_token_blacklist.reason，便于审计。 */
public final class RevokeReason {
    /** 主动登出。 */
    public static final String LOGOUT = "LOGOUT";
    /** 已轮换/已吊销的刷新令牌再次被使用，判定为重放，整会话连带吊销。 */
    public static final String REFRESH_REPLAY = "REFRESH_REPLAY";
    /** 修改密码：该用户全部会话连带失效。 */
    public static final String PASSWORD_CHANGE = "PASSWORD_CHANGE";

    /** 会让仍在有效期内的访问令牌立即失效的会话级原因（过滤链据此连坐）。 */
    public static final String[] SESSION_LEVEL_REASONS = {REFRESH_REPLAY, PASSWORD_CHANGE};

    private RevokeReason() {
    }
}
