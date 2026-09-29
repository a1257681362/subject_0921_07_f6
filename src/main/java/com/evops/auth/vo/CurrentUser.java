package com.evops.auth.vo;

import java.time.LocalDateTime;

/** /api/auth/me 返回的当前登录人信息（由服务端按令牌内 uid 现查，不依赖令牌中的明文）。 */
public class CurrentUser {

    private Long userId;
    private String username;
    private String displayName;
    private LocalDateTime lastLoginTime;

    public CurrentUser() {
    }

    public CurrentUser(Long userId, String username, String displayName, LocalDateTime lastLoginTime) {
        this.userId = userId;
        this.username = username;
        this.displayName = displayName;
        this.lastLoginTime = lastLoginTime;
    }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public LocalDateTime getLastLoginTime() { return lastLoginTime; }
    public void setLastLoginTime(LocalDateTime lastLoginTime) { this.lastLoginTime = lastLoginTime; }
}
