package com.evops.auth.jwt;

/** 令牌种类：访问令牌 / 刷新令牌，刷新接口拒绝访问令牌、业务接口拒绝刷新令牌。 */
public enum TokenType {
    ACCESS,
    REFRESH
}
