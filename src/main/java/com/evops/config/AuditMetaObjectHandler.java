package com.evops.config;

import com.baomidou.mybatisplus.core.handlers.MetaObjectHandler;
import com.evops.auth.AuthPrincipal;
import org.apache.ibatis.reflection.MetaObject;
import org.apache.shiro.SecurityUtils;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * 审计字段自动填充。优先从 Shiro 当前主体取登录用户 ID（JWT 无状态请求）；
 * 取不到（定时任务、启动补跑、登录前的请求等）回落 system=0。
 */
@Component
public class AuditMetaObjectHandler implements MetaObjectHandler {

    private static final Long SYSTEM_USER = 0L;

    @Override
    public void insertFill(MetaObject metaObject) {
        Long userId = currentUserId();
        LocalDateTime now = LocalDateTime.now();
        fillIfPresent("createTime", now, metaObject);
        fillIfPresent("updateTime", now, metaObject);
        fillIfPresent("createBy", userId, metaObject);
        fillIfPresent("updateBy", userId, metaObject);
    }

    @Override
    public void updateFill(MetaObject metaObject) {
        fillIfPresent("updateTime", LocalDateTime.now(), metaObject);
        fillIfPresent("updateBy", currentUserId(), metaObject);
    }

    private Long currentUserId() {
        try {
            Object principal = SecurityUtils.getSubject().getPrincipal();
            if (principal instanceof AuthPrincipal) {
                return ((AuthPrincipal) principal).getUserId();
            }
        } catch (Exception e) {
            // 无 Web 请求上下文（调度线程等）：回落 system
        }
        return SYSTEM_USER;
    }

    private void fillIfPresent(String field, Object value, MetaObject metaObject) {
        if (metaObject.hasSetter(field) && getFieldValByName(field, metaObject) == null) {
            setFieldValByName(field, value, metaObject);
        }
    }
}
