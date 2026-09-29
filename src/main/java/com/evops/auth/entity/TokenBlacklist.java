package com.evops.auth.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 令牌黑名单：登出/强制失效时按访问令牌 jti 登记，到期（令牌自身 exp）即可物理清理。
 * 不继承 BaseEntity：该表只有登记列，无更新列。
 */
@Data
@TableName("t_token_blacklist")
public class TokenBlacklist {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String jti;
    /** ACCESS / REFRESH。 */
    private String tokenType;
    private String reason;
    private Long userId;
    private LocalDateTime expireTime;

    @TableField(fill = FieldFill.INSERT)
    private Long createBy;

    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createTime;
}
