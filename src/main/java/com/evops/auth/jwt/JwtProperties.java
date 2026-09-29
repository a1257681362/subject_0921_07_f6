package com.evops.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 无状态会话配置（auth.jwt.*）。
 * 生产环境必须显式配置 Base64 密钥（建议 ≥32 字节，可用 openssl rand -base64 32 生成）；
 * 留空时每次启动随机生成，重启后所有已签发令牌立即失效（仅适合本机开发/测试）。
 */
@Component
@ConfigurationProperties(prefix = "auth.jwt")
public class JwtProperties {

    /** HS256 密钥，Base64 编码；为空则启动时随机生成。 */
    private String secret = "";

    /** 访问令牌有效期（分钟）。 */
    private long accessTokenTtlMinutes = 30;

    /** 刷新令牌有效期（天），每次刷新顺延一个完整周期。 */
    private long refreshTokenTtlDays = 7;

    /** 签发方标识。 */
    private String issuer = "evops";

    /** 时钟偏移容忍（秒），校验 exp 时放宽。 */
    private long clockSkewSeconds = 60;

    /**
     * Shiro 过滤链是否强制鉴权。true（默认）=业务接口一律校验 JWT；
     * false=全部放行，仅用于排障/历史测试，生产必须保持 true。
     */
    private boolean filterEnabled = true;

    /** 黑名单/过期刷新令牌清理调度开关。 */
    private boolean schedulingEnabled = true;

    /** 清理定时表达式（默认每日 03:30，避开 02:10 的勾稽作业）。 */
    private String cleanupCron = "0 30 3 * * ?";

    public String getSecret() { return secret; }
    public void setSecret(String secret) { this.secret = secret; }
    public long getAccessTokenTtlMinutes() { return accessTokenTtlMinutes; }
    public void setAccessTokenTtlMinutes(long accessTokenTtlMinutes) { this.accessTokenTtlMinutes = accessTokenTtlMinutes; }
    public long getRefreshTokenTtlDays() { return refreshTokenTtlDays; }
    public void setRefreshTokenTtlDays(long refreshTokenTtlDays) { this.refreshTokenTtlDays = refreshTokenTtlDays; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public long getClockSkewSeconds() { return clockSkewSeconds; }
    public void setClockSkewSeconds(long clockSkewSeconds) { this.clockSkewSeconds = clockSkewSeconds; }
    public boolean isFilterEnabled() { return filterEnabled; }
    public void setFilterEnabled(boolean filterEnabled) { this.filterEnabled = filterEnabled; }
    public boolean isSchedulingEnabled() { return schedulingEnabled; }
    public void setSchedulingEnabled(boolean schedulingEnabled) { this.schedulingEnabled = schedulingEnabled; }
    public String getCleanupCron() { return cleanupCron; }
    public void setCleanupCron(String cleanupCron) { this.cleanupCron = cleanupCron; }
}
