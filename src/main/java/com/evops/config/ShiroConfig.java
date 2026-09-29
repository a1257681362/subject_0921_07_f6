package com.evops.config;

import com.evops.auth.jwt.JwtProperties;
import com.evops.auth.jwt.JwtService;
import com.evops.auth.mapper.SysUserMapper;
import com.evops.auth.service.TokenStateService;
import com.evops.auth.shiro.JwtAuthFilter;
import com.evops.auth.shiro.JwtRealm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;

/**
 * Shiro 无状态鉴权装配：
 * - 自定义 JwtRealm 只做令牌状态复核，不使用账号密码 Realm；
 * - 关闭服务端会话：纯内存 SessionManager（不接 HttpSession、不发 JSESSIONID）+
 *   SubjectFactory 禁止建会话 + SubjectDAO 关闭会话存储，认证态只活在当前请求；
 * - jwt 过滤器交给 Shiro 过滤链按名引用（filterMap 收集容器内 Filter bean），
 *   同时关闭 Boot 对它的独立注册，避免一次请求过两遍。
 */
@Configuration
public class ShiroConfig {

    @Bean
    public JwtRealm jwtRealm(SysUserMapper sysUserMapper, TokenStateService tokenStateService) {
        return new JwtRealm(sysUserMapper, tokenStateService);
    }

    @Bean
    public DefaultWebSecurityManager securityManager(JwtRealm jwtRealm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager(jwtRealm);

        // 纯内存会话管理器：不挂 Servlet 容器会话，不启动会话校验调度
        DefaultSessionManager sessionManager = new DefaultSessionManager();
        sessionManager.setSessionValidationSchedulerEnabled(false);
        securityManager.setSessionManager(sessionManager);

        // 禁止 Subject 创建会话：JWT 无状态的标准开关
        securityManager.setSubjectFactory(new DefaultWebSubjectFactory() {
            @Override
            public Subject createSubject(SubjectContext context) {
                context.setSessionCreationEnabled(false);
                return super.createSubject(context);
            }
        });

        // Subject 状态不落会话存储
        DefaultSessionStorageEvaluator storageEvaluator = new DefaultSessionStorageEvaluator();
        storageEvaluator.setSessionStorageEnabled(false);
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        subjectDAO.setSessionStorageEvaluator(storageEvaluator);
        securityManager.setSubjectDAO(subjectDAO);

        // 无状态不使用记住我：置空后响应不再带任何 Shiro Cookie（含 rememberMe=deleteMe）
        securityManager.setRememberMeManager(null);

        return securityManager;
    }

    /** Shiro 链按 bean 名 "jwt" 引用本过滤器。 */
    @Bean(name = "jwt")
    public JwtAuthFilter jwtAuthFilter(JwtService jwtService, ObjectMapper objectMapper) {
        return new JwtAuthFilter(jwtService, objectMapper);
    }

    /** 阻止 Spring Boot 把 jwt 过滤器再注册到 Servlet 容器（它只应由 Shiro 总过滤器调度）。 */
    @Bean
    public FilterRegistrationBean<Filter> jwtFilterRegistration(JwtAuthFilter jwtAuthFilter) {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>(jwtAuthFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition(JwtProperties properties) {
        DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
        chain.addPathDefinition("/api/health", "anon");
        chain.addPathDefinition("/error", "anon");

        if (!properties.isFilterEnabled()) {
            // 应急/测试开关：auth.jwt.filter-enabled=false 时全部放行，生产必须保持 true
            chain.addPathDefinition("/**", "anon");
            return chain;
        }

        // 登录、刷新不要求已有令牌（刷新凭一次性刷新令牌自证）；其余一律 jwt
        chain.addPathDefinition("/api/auth/login", "anon");
        chain.addPathDefinition("/api/auth/refresh", "anon");
        chain.addPathDefinition("/**", "jwt");
        return chain;
    }
}
