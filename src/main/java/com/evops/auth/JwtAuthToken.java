package com.evops.auth;

import com.evops.auth.jwt.JwtClaims;
import org.apache.shiro.authc.AuthenticationToken;

/** Shiro 认证令牌：包装已通过签名校验的 JWT 声明，供 JwtRealm 做黑名单/会话/用户状态复核。 */
public class JwtAuthToken implements AuthenticationToken {

    private final transient JwtClaims claims;

    public JwtAuthToken(JwtClaims claims) {
        this.claims = claims;
    }

    public JwtClaims getClaims() {
        return claims;
    }

    @Override
    public Object getPrincipal() {
        return claims.getUserId();
    }

    @Override
    public Object getCredentials() {
        return claims.getJti();
    }
}
