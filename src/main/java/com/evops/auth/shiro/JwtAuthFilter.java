package com.evops.auth.shiro;

import com.evops.auth.JwtAuthToken;
import com.evops.auth.jwt.JwtClaims;
import com.evops.auth.jwt.JwtService;
import com.evops.auth.jwt.JwtVerificationException;
import com.evops.auth.jwt.TokenType;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shiro 无状态认证过滤器：从 Authorization: Bearer 取访问令牌，
 * 先本地验签（JwtService），再交 JwtRealm 做黑名单/会话/用户复核（subject.login）。
 * 任何环节失败一律 401 + 统一 JSON 结构，不做登录页跳转（接口无页面）。
 */
public class JwtAuthFilter extends AccessControlFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    public JwtAuthFilter(JwtService jwtService, ObjectMapper objectMapper) {
        this.jwtService = jwtService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        // 无状态：每请求都在 onAccessDenied 里现验令牌，不依赖任何既有会话/记住我
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            writeUnauthorized(response, "未登录或登录已过期，请重新登录");
            return false;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        JwtClaims claims;
        try {
            claims = jwtService.verify(token);
        } catch (JwtVerificationException e) {
            log.debug("访问令牌验签失败：{}", e.getMessage());
            writeUnauthorized(response, "登录已过期，请重新登录");
            return false;
        }
        if (claims.getType() != TokenType.ACCESS) {
            writeUnauthorized(response, "令牌类型不正确，请使用访问令牌");
            return false;
        }
        try {
            // realm 内完成黑名单/会话连坐/用户状态复核
            getSubject(request, response).login(new JwtAuthToken(claims));
            return true;
        } catch (AuthenticationException e) {
            log.debug("令牌状态复核失败：{}", e.getMessage());
            writeUnauthorized(response, "登录已失效，请重新登录");
            return false;
        }
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("message", message);
        body.put("data", null);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
