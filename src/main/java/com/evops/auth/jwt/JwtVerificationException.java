package com.evops.auth.jwt;

/** JWT 校验失败统一异常：签名错误、过期、格式不合法等，调用方转成 Shiro 认证异常或业务异常。 */
public class JwtVerificationException extends RuntimeException {
    public JwtVerificationException(String message) {
        super(message);
    }

    public JwtVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
