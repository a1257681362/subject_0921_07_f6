package com.evops.auth.jwt;

/** 签发结果：紧凑串 + 服务端台账锚点 jti + 有效期信息。 */
public class IssuedToken {

    private final String token;
    private final String jti;
    private final long issuedAtEpochMilli;
    private final long expiresAtEpochMilli;

    public IssuedToken(String token, String jti, long issuedAtEpochMilli, long expiresAtEpochMilli) {
        this.token = token;
        this.jti = jti;
        this.issuedAtEpochMilli = issuedAtEpochMilli;
        this.expiresAtEpochMilli = expiresAtEpochMilli;
    }

    public String getToken() { return token; }
    public String getJti() { return jti; }
    public long getIssuedAtEpochMilli() { return issuedAtEpochMilli; }
    public long getExpiresAtEpochMilli() { return expiresAtEpochMilli; }

    /** 剩余有效秒数。 */
    public long getExpiresInSeconds() {
        return Math.max(0, (expiresAtEpochMilli - System.currentTimeMillis()) / 1000);
    }
}
