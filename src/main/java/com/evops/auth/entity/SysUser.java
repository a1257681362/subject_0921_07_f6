package com.evops.auth.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import com.baomidou.mybatisplus.annotation.Version;
import com.evops.common.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.time.LocalDateTime;

/** 系统用户。口令只存盐 + 迭代 SHA-256 哈希。 */
@Data
@EqualsAndHashCode(callSuper = true)
@TableName("t_sys_user")
public class SysUser extends BaseEntity {
    private String username;
    private String displayName;
    private String passwordHash;
    private String salt;
    /** ACTIVE 启用 / DISABLED 停用。 */
    private String status;
    private LocalDateTime lastLoginTime;

    @Version
    private Integer version = 0;
}
