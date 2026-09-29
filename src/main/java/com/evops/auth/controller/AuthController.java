package com.evops.auth.controller;

import com.evops.auth.AuthPrincipal;
import com.evops.auth.dto.ChangePasswordRequest;
import com.evops.auth.dto.LoginRequest;
import com.evops.auth.dto.LogoutRequest;
import com.evops.auth.dto.RefreshRequest;
import com.evops.auth.service.AuthService;
import com.evops.auth.vo.CurrentUser;
import com.evops.auth.vo.TokenPair;
import com.evops.common.ApiResponse;
import org.apache.shiro.SecurityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

/**
 * 认证接口：登录、刷新、登出、当前登录人。
 * 登录/刷新在过滤链中放行（凭令牌自证）；登出与 /me 必须携带有效访问令牌。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ApiResponse<TokenPair> login(@Valid @RequestBody LoginRequest request) {
        return ApiResponse.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ApiResponse<TokenPair> refresh(@Valid @RequestBody RefreshRequest request) {
        return ApiResponse.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(@RequestBody(required = false) LogoutRequest request) {
        AuthPrincipal principal = (AuthPrincipal) SecurityUtils.getSubject().getPrincipal();
        String refreshToken = request != null ? request.getRefreshToken() : null;
        authService.logout(principal, refreshToken);
        return ApiResponse.ok(null);
    }

    @GetMapping("/me")
    public ApiResponse<CurrentUser> me() {
        AuthPrincipal principal = (AuthPrincipal) SecurityUtils.getSubject().getPrincipal();
        return ApiResponse.ok(authService.currentUser(principal.getUserId()));
    }

    @PostMapping("/change-password")
    public ApiResponse<Void> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        AuthPrincipal principal = (AuthPrincipal) SecurityUtils.getSubject().getPrincipal();
        authService.changePassword(principal.getUserId(), request.getOldPassword(), request.getNewPassword());
        return ApiResponse.ok(null);
    }
}
