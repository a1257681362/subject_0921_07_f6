package com.evops.auth.dto;

/** 登出请求体：refreshToken 可选——带上则刷新令牌一并吊销；不带只让当前访问令牌失效。 */
public class LogoutRequest {

    private String refreshToken;

    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
}
