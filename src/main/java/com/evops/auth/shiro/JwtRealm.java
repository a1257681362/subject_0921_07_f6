package com.evops.auth.shiro;

import com.evops.auth.AuthPrincipal;
import com.evops.auth.JwtAuthToken;
import com.evops.auth.entity.SysUser;
import com.evops.auth.jwt.JwtClaims;
import com.evops.auth.jwt.TokenType;
import com.evops.auth.mapper.SysUserMapper;
import com.evops.auth.service.TokenStateService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * JWT 领域：过滤器已验签的令牌在此做服务端状态复核——
 * 1) 必须是访问令牌；2) jti 未登出拉黑；3) 会话未因重放被连坐吊销；4) 用户仍存在且启用。
 * 通过后主体为 AuthPrincipal（只含定位信息），不落服务端会话。
 */
public class JwtRealm extends AuthorizingRealm {

    private final SysUserMapper userMapper;
    private final TokenStateService tokenStateService;

    public JwtRealm(SysUserMapper userMapper, TokenStateService tokenStateService) {
        this.userMapper = userMapper;
        this.tokenStateService = tokenStateService;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtAuthToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        JwtClaims claims = ((JwtAuthToken) token).getClaims();
        if (claims.getType() != TokenType.ACCESS) {
            throw new IncorrectCredentialsException("令牌类型不正确");
        }
        if (tokenStateService.isBlacklisted(claims.getJti())) {
            throw new IncorrectCredentialsException("令牌已失效，请重新登录");
        }
        if (tokenStateService.isSessionCompromised(claims.getSessionId())) {
            throw new IncorrectCredentialsException("登录状态因安全原因已失效，请重新登录");
        }
        SysUser user = userMapper.selectById(claims.getUserId());
        if (user == null || !"ACTIVE".equals(user.getStatus())) {
            throw new UnknownAccountException("用户不存在或已停用");
        }
        AuthPrincipal principal = new AuthPrincipal(user.getId(), user.getUsername(),
                claims.getSessionId(), claims.getJti(), claims.getExpiresAtEpochSecond());
        return new SimpleAuthenticationInfo(principal, claims.getJti(), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 当前无功能级权限细分，所有登录用户角色一致；后续接角色体系时在此扩展。
        return new SimpleAuthorizationInfo();
    }
}
