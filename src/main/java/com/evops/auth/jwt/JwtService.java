package com.evops.auth.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * JWT 签发与校验（HS256，紧凑序列化三段式）。仅依赖 JDK 与 Jackson，不引入第三方 JWT 库。
 *
 * 令牌声明只放定位信息：uid 用户ID、sid 会话ID、jti 令牌ID、typ 类型、iss/iat/nbf/exp；
 * 不放用户名、姓名等敏感明文，敏感信息由服务端按 uid 现查。
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    private static final String ALGORITHM = "HmacSHA256";
    private static final String HEADER = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    private final JwtProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Base64.Encoder urlEncoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder urlDecoder = Base64.getUrlDecoder();

    private byte[] signingKey;
    private String encodedHeader;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        String secret = properties.getSecret();
        if (secret != null && !secret.trim().isEmpty()) {
            byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(secret.trim());
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(
                        "auth.jwt.secret 不是合法的 Base64，请用 openssl rand -base64 32 重新生成", e);
            }
            if (decoded.length < 32) {
                throw new IllegalStateException("auth.jwt.secret 解码后不足 32 字节（256 位），拒绝启动");
            }
            signingKey = decoded;
        } else {
            signingKey = new byte[32];
            new SecureRandom().nextBytes(signingKey);
            log.warn("auth.jwt.secret 未配置，已生成临时随机密钥；服务重启后所有已签发令牌失效，"
                    + "生产环境必须配置固定密钥（openssl rand -base64 32）");
        }
        encodedHeader = urlEncoder.encodeToString(HEADER.getBytes(StandardCharsets.UTF_8));
    }

    /** 生成随机令牌/会话 ID（32 位十六进制）。 */
    public String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /** 当前毫秒时间，单独成方法便于测试模拟过期。 */
    protected long nowMillis() {
        return System.currentTimeMillis();
    }

    /** 签发访问/刷新令牌。 */
    public IssuedToken issue(Long userId, String sessionId, String jti, TokenType type) {
        long now = nowMillis();
        long ttlMillis = type == TokenType.ACCESS
                ? properties.getAccessTokenTtlMinutes() * 60_000L
                : properties.getRefreshTokenTtlDays() * 24L * 60 * 60_000L;
        long exp = now + ttlMillis;

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", properties.getIssuer());
        claims.put("uid", userId);
        claims.put("sid", sessionId);
        claims.put("jti", jti);
        claims.put("typ", type.name().toLowerCase());
        claims.put("iat", now / 1000);
        claims.put("nbf", now / 1000);
        claims.put("exp", exp / 1000);

        try {
            String payload = urlEncoder.encodeToString(
                    objectMapper.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8));
            String signingInput = encodedHeader + "." + payload;
            String signature = urlEncoder.encodeToString(hmac(signingInput));
            return new IssuedToken(signingInput + "." + signature, jti, now, exp);
        } catch (Exception e) {
            throw new IllegalStateException("令牌签发失败", e);
        }
    }

    /**
     * 校验令牌：必须三段、alg 固定 HS256、签名一致、签发方一致、在 nbf/exp 窗口内、声明完整。
     * 任何一项不符抛 JwtVerificationException。
     */
    public JwtClaims verify(String token) {
        if (token == null || token.isEmpty()) {
            throw new JwtVerificationException("令牌为空");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new JwtVerificationException("令牌格式不正确");
        }
        // 先验头：alg 必须固定 HS256，拒绝 alg=none 与其他算法（防算法混淆）
        try {
            JsonNode headerNode = objectMapper.readTree(urlDecoder.decode(parts[0]));
            if (!"HS256".equals(headerNode.path("alg").asText(null))) {
                throw new JwtVerificationException("令牌算法不受支持");
            }
        } catch (JwtVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new JwtVerificationException("令牌头解析失败", e);
        }

        // 常量时间比对签名
        byte[] expected = hmac(parts[0] + "." + parts[1]);
        byte[] actual;
        try {
            actual = urlDecoder.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new JwtVerificationException("令牌签名格式不正确", e);
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new JwtVerificationException("令牌签名校验失败");
        }

        JsonNode claims;
        try {
            claims = objectMapper.readTree(urlDecoder.decode(parts[1]));
        } catch (Exception e) {
            throw new JwtVerificationException("令牌声明解析失败", e);
        }

        String iss = claims.path("iss").asText(null);
        if (!properties.getIssuer().equals(iss)) {
            throw new JwtVerificationException("令牌签发方不匹配");
        }
        JsonNode uidNode = claims.get("uid");
        JsonNode sidNode = claims.get("sid");
        JsonNode jtiNode = claims.get("jti");
        JsonNode typNode = claims.get("typ");
        if (uidNode == null || !uidNode.canConvertToLong()
                || sidNode == null || sidNode.asText().isEmpty()
                || jtiNode == null || jtiNode.asText().isEmpty()
                || typNode == null || typNode.asText().isEmpty()) {
            throw new JwtVerificationException("令牌声明不完整");
        }
        TokenType type;
        try {
            type = TokenType.valueOf(typNode.asText().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new JwtVerificationException("令牌类型不合法");
        }

        long now = nowMillis() / 1000;
        long skew = properties.getClockSkewSeconds();
        long nbf = claims.path("nbf").asLong(0);
        long exp = claims.path("exp").asLong(0);
        if (exp <= 0) {
            throw new JwtVerificationException("令牌缺少有效期");
        }
        if (now + skew < nbf) {
            throw new JwtVerificationException("令牌尚未生效");
        }
        if (now - skew > exp) {
            throw new JwtVerificationException("令牌已过期");
        }
        return new JwtClaims(uidNode.asLong(), sidNode.asText(), jtiNode.asText(), type, exp);
    }

    private byte[] hmac(String input) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(signingKey, ALGORITHM));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC 计算失败", e);
        }
    }
}
