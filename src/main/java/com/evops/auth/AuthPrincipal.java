package com.evops.auth;

/**
 * 登录后的主体信息（Shiro Subject 的 principal）。
 * 登录态持用户名/显示名（来自库）；JWT 业务请求态只有用户ID与定位字段，
 * 需要展示信息时由服务端按 userId 现查。
 */
public class AuthPrincipal {

    private final Long userId;
    private final String username;
    private final String sessionId;
    private final String jti;
    /** 访问令牌自身到期时间（秒级 epoch），登出登记黑名单时按此设保留期限。 */
    private final long expiresAtEpochSecond;

    public AuthPrincipal(Long userId, String username, String sessionId, String jti, long expiresAtEpochSecond) {
        this.userId = userId;
        this.username = username;
        this.sessionId = sessionId;
        this.jti = jti;
        this.expiresAtEpochSecond = expiresAtEpochSecond;
    }

    public Long getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getSessionId() { return sessionId; }
    public String getJti() { return jti; }
    public long getExpiresAtEpochSecond() { return expiresAtEpochSecond; }
}
