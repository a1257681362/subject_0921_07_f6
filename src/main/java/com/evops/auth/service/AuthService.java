package com.evops.auth.service;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.evops.auth.AuthPrincipal;
import com.evops.auth.PasswordHasher;
import com.evops.auth.RevokeReason;
import com.evops.auth.TokenStatus;
import com.evops.auth.dto.LoginRequest;
import com.evops.auth.dto.RefreshRequest;
import com.evops.auth.entity.RefreshToken;
import com.evops.auth.entity.SysUser;
import com.evops.auth.jwt.IssuedToken;
import com.evops.auth.jwt.JwtClaims;
import com.evops.auth.jwt.JwtService;
import com.evops.auth.jwt.JwtVerificationException;
import com.evops.auth.jwt.TokenType;
import com.evops.auth.mapper.RefreshTokenMapper;
import com.evops.auth.mapper.SysUserMapper;
import com.evops.auth.vo.CurrentUser;
import com.evops.auth.vo.TokenPair;
import com.evops.common.BusinessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * 无状态会话认证服务。
 *
 * 双令牌：访问令牌（短效，业务接口携带，登出时入黑名单）；刷新令牌（长效，只对 /refresh 使用，
 * 服务端有唯一台账行做状态锚点）。刷新即轮换：旧行 ACTIVE→ROTATED 指向新行，旧令牌立即失效；
 * 若一张已轮换/已吊销的刷新令牌再次出现，判为重放，整条会话（同 sessionId）连带吊销。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final SysUserMapper userMapper;
    private final RefreshTokenMapper refreshTokenMapper;
    private final TokenStateService tokenStateService;
    private final JwtService jwtService;

    public AuthService(SysUserMapper userMapper,
                       RefreshTokenMapper refreshTokenMapper,
                       TokenStateService tokenStateService,
                       JwtService jwtService) {
        this.userMapper = userMapper;
        this.refreshTokenMapper = refreshTokenMapper;
        this.tokenStateService = tokenStateService;
        this.jwtService = jwtService;
    }

    /** 用户名口令登录，成功下发双令牌并建立刷新令牌台账行。 */
    @Transactional
    public TokenPair login(LoginRequest request) {
        SysUser user = userMapper.selectOne(new LambdaQueryWrapper<SysUser>()
                .eq(SysUser::getUsername, request.getUsername()));
        // 用户不存在与口令错误返回同一句话，避免账号枚举
        if (user == null
                || !PasswordHasher.matches(request.getPassword(), user.getSalt(), user.getPasswordHash())) {
            throw new BusinessException("用户名或密码不正确");
        }
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new BusinessException("账号已停用，请联系管理员");
        }

        String sessionId = jwtService.newId();
        TokenPair pair = issuePair(user.getId(), sessionId, null);

        SysUser touch = new SysUser();
        touch.setId(user.getId());
        touch.setLastLoginTime(LocalDateTime.now());
        userMapper.updateById(touch);
        log.info("用户 {} 登录成功，会话 {}", user.getUsername(), sessionId);
        return pair;
    }

    /**
     * 刷新：一次性轮换。
     * 正常路径：台账行 ACTIVE → 乐观锁置 ROTATED 指向新行，签发新双令牌（会话不变）。
     * 重放路径：行已 ROTATED/REVOKED 却再次出现，吊销同会话所有有效令牌并拒绝。
     */
    @Transactional
    public TokenPair refresh(RefreshRequest request) {
        JwtClaims claims;
        try {
            claims = jwtService.verify(request.getRefreshToken());
        } catch (JwtVerificationException e) {
            throw new BusinessException("刷新令牌无效或已过期，请重新登录");
        }
        if (claims.getType() != TokenType.REFRESH) {
            throw new BusinessException("令牌类型不正确，请使用刷新令牌");
        }

        RefreshToken row = refreshTokenMapper.selectOne(new LambdaQueryWrapper<RefreshToken>()
                .eq(RefreshToken::getTokenJti, claims.getJti()));
        if (row == null) {
            throw new BusinessException("刷新令牌无效，请重新登录");
        }

        if (TokenStatus.ACTIVE.equals(row.getStatus())) {
            return rotate(row);
        }
        // 已 ROTATED/REVOKED 的令牌再次使用 = 重放（令牌可能已泄露），整条会话连坐吊销。
        // 吊销走独立事务：本方法随后抛业务异常会回滚外层事务，吊销必须先提交。
        tokenStateService.revokeSessionInNewTx(row.getSessionId(), claims.getJti(),
                claims.getUserId(), claims.getExpiresAtEpochSecond(), RevokeReason.REFRESH_REPLAY);
        log.warn("检测到刷新令牌重放，已吊销会话 {}（用户 {}）", row.getSessionId(), row.getUserId());
        throw new BusinessException("刷新令牌已被使用，为保障账号安全该登录已全部失效，请重新登录");
    }

    private TokenPair rotate(RefreshToken current) {
        SysUser user = userMapper.selectById(current.getUserId());
        if (user == null || !"ACTIVE".equals(user.getStatus())) {
            throw new BusinessException("账号已停用，请联系管理员");
        }

        String newRefreshJti = jwtService.newId();

        // 乐观锁 CAS：并发两笔刷新只有一笔能把 ACTIVE 行置成 ROTATED
        RefreshToken rotated = new RefreshToken();
        rotated.setId(current.getId());
        rotated.setVersion(current.getVersion());
        rotated.setStatus(TokenStatus.ROTATED);
        rotated.setRotatedToJti(newRefreshJti);
        // /refresh 为 anon 路径、无 Shiro 主体，审计列显式带用户 ID（否则处理器回落 0）
        rotated.setUpdateBy(user.getId());
        int changed = refreshTokenMapper.updateById(rotated);
        if (changed == 0) {
            // 并发的另一笔已完成轮换，本笔拒绝即可（不能吊销会话，否则会误伤刚轮换出的新令牌）
            throw new BusinessException("刷新令牌刚已使用，请勿重复提交，请用最新令牌重试");
        }

        TokenPair pair = issuePair(user.getId(), current.getSessionId(), newRefreshJti);
        log.info("会话 {} 完成刷新令牌轮换", current.getSessionId());
        return pair;
    }    /**
     * 登出：访问令牌按 jti 进黑名单（保留到其自身 exp，到期自动清理）；
     * 刷新令牌若仍 ACTIVE 则置 REVOKED（已轮换的不动，不影响同会话后续令牌）。
     * 刷新令牌缺失/过期不影响登出成功。
     */
    @Transactional
    public void logout(AuthPrincipal principal, String refreshTokenValue) {
        if (principal == null) {
            return;
        }
        tokenStateService.blacklist(principal.getJti(), TokenType.ACCESS,
                RevokeReason.LOGOUT, principal.getUserId(), principal.getExpiresAtEpochSecond());

        if (refreshTokenValue == null || refreshTokenValue.trim().isEmpty()) {
            log.info("用户 {} 登出（访问令牌已入黑名单）", principal.getUserId());
            return;
        }
        JwtClaims claims;
        try {
            claims = jwtService.verify(refreshTokenValue);
        } catch (JwtVerificationException e) {
            // 刷新令牌已过期等：访问令牌已入黑名单，登出照常成功
            log.info("用户 {} 登出时刷新令牌已失效，跳过台账吊销", principal.getUserId());
            return;
        }
        if (claims.getType() != TokenType.REFRESH || !claims.getSessionId().equals(principal.getSessionId())) {
            return;
        }
        tokenStateService.blacklist(claims.getJti(), TokenType.REFRESH,
                RevokeReason.LOGOUT, principal.getUserId(), claims.getExpiresAtEpochSecond());
        int changed = refreshTokenMapper.update(null, new LambdaUpdateWrapper<RefreshToken>()
                .eq(RefreshToken::getTokenJti, claims.getJti())
                .eq(RefreshToken::getStatus, TokenStatus.ACTIVE)
                .set(RefreshToken::getStatus, TokenStatus.REVOKED)
                .set(RefreshToken::getRevokeReason, RevokeReason.LOGOUT));
        log.info("用户 {} 登出，刷新令牌吊销 {} 行", principal.getUserId(), changed);
    }

    /** /api/auth/me：按访问令牌里的 uid 现查用户信息，不使用令牌中的明文（令牌里也没有）。 */
    public CurrentUser currentUser(Long userId) {
        SysUser user = userMapper.selectById(userId);
        if (user == null || !"ACTIVE".equals(user.getStatus())) {
            throw new BusinessException("用户不存在或已停用");
        }
        return new CurrentUser(user.getId(), user.getUsername(), user.getDisplayName(), user.getLastLoginTime());
    }

    /**
     * 修改密码：校验原口令后换新盐与新哈希；随后吊销该用户所有仍 ACTIVE 的会话
     * （原因 PASSWORD_CHANGE，会话级连坐让旧访问令牌也立即失效），需用新口令重新登录。
     */
    @Transactional
    public void changePassword(Long userId, String oldPassword, String newPassword) {
        SysUser user = userMapper.selectById(userId);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        if (!PasswordHasher.matches(oldPassword, user.getSalt(), user.getPasswordHash())) {
            throw new BusinessException("原密码不正确");
        }
        String newSalt = PasswordHasher.randomSalt();
        SysUser update = new SysUser();
        update.setId(user.getId());
        update.setVersion(user.getVersion());
        update.setSalt(newSalt);
        update.setPasswordHash(PasswordHasher.hash(newPassword, newSalt));
        int changed = userMapper.updateById(update);
        if (changed == 0) {
            throw new BusinessException("用户信息已变更，请刷新后重试");
        }

        refreshTokenMapper.update(null, new LambdaUpdateWrapper<RefreshToken>()
                .eq(RefreshToken::getUserId, userId)
                .eq(RefreshToken::getStatus, TokenStatus.ACTIVE)
                .set(RefreshToken::getStatus, TokenStatus.REVOKED)
                .set(RefreshToken::getRevokeReason, RevokeReason.PASSWORD_CHANGE));
        log.info("用户 {} 修改密码，全部有效会话已吊销", user.getUsername());
    }

    private TokenPair issuePair(Long userId, String sessionId, String refreshJti) {
        String refreshId = refreshJti != null ? refreshJti : jwtService.newId();
        IssuedToken access = jwtService.issue(userId, sessionId, jwtService.newId(), TokenType.ACCESS);
        IssuedToken refresh = jwtService.issue(userId, sessionId, refreshId, TokenType.REFRESH);

        RefreshToken row = new RefreshToken();
        row.setUserId(userId);
        row.setTokenJti(refreshId);
        row.setSessionId(sessionId);
        row.setStatus(TokenStatus.ACTIVE);
        row.setExpiresAt(LocalDateTime.ofInstant(
                Instant.ofEpochMilli(refresh.getExpiresAtEpochMilli()), ZoneId.systemDefault()));
        row.setCreateBy(userId);
        row.setUpdateBy(userId);
        refreshTokenMapper.insert(row);

        return new TokenPair(access.getToken(), refresh.getToken(),
                access.getExpiresInSeconds(), refresh.getExpiresInSeconds());
    }
}
