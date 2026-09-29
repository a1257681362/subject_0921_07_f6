package com.evops.auth.vo;

/** 登录/刷新成功后下发的双令牌。令牌本身不含敏感明文。 */
public class TokenPair {

    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    /** 访问令牌剩余秒数。 */
    private long expiresIn;
    /** 刷新令牌剩余秒数。 */
    private long refreshExpiresIn;

    public TokenPair() {
    }

    public TokenPair(String accessToken, String refreshToken, long expiresIn, long refreshExpiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
    }

    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(long expiresIn) { this.expiresIn = expiresIn; }
    public long getRefreshExpiresIn() { return refreshExpiresIn; }
    public void setRefreshExpiresIn(long refreshExpiresIn) { this.refreshExpiresIn = refreshExpiresIn; }
}
