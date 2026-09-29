package com.evops.auth.jwt;

/** 校验通过后的令牌声明。只含定位信息，不含用户名/姓名/手机号等敏感明文。 */
public class JwtClaims {

    private final Long userId;
    private final String sessionId;
    private final String jti;
    private final TokenType type;
    private final long expiresAtEpochSecond;

    public JwtClaims(Long userId, String sessionId, String jti, TokenType type, long expiresAtEpochSecond) {
        this.userId = userId;
        this.sessionId = sessionId;
        this.jti = jti;
        this.type = type;
        this.expiresAtEpochSecond = expiresAtEpochSecond;
    }

    public Long getUserId() { return userId; }
    public String getSessionId() { return sessionId; }
    public String getJti() { return jti; }
    public TokenType getType() { return type; }
    public long getExpiresAtEpochSecond() { return expiresAtEpochSecond; }
}
