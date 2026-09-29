package com.evops.auth.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** JWT 签发/校验：往返、过期、篡改、算法混淆、密钥隔离、声明不含敏感明文。 */
class JwtServiceTest {

    private JwtProperties properties;

    @BeforeEach
    void setUp() {
        properties = new JwtProperties();
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        properties.setSecret(Base64.getEncoder().encodeToString(key));
    }

    @Test
    void issueAndVerify_roundTrip() {
        JwtService service = new JwtService(properties);
        service.init();

        IssuedToken issued = service.issue(1001L, "sid-1", "jti-1", TokenType.ACCESS);
        JwtClaims claims = service.verify(issued.getToken());

        assertEquals(1001L, claims.getUserId().longValue());
        assertEquals("sid-1", claims.getSessionId());
        assertEquals("jti-1", claims.getJti());
        assertEquals(TokenType.ACCESS, claims.getType());
        assertTrue(issued.getExpiresInSeconds() > 29 * 60);
    }

    @Test
    void verify_rejectsTamperedSignature() {
        JwtService service = new JwtService(properties);
        service.init();
        String token = service.issue(1L, "s", "j", TokenType.ACCESS).getToken();
        char last = token.charAt(token.length() - 1);
        String tampered = token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
        assertThrows(JwtVerificationException.class, () -> service.verify(tampered));
    }

    @Test
    void verify_rejectsAlgNone() {
        JwtService service = new JwtService(properties);
        service.init();
        // 手工构造 alg=none 的头；签名段留空
        String noneHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
        String token = service.issue(1L, "s", "j", TokenType.ACCESS).getToken();
        String payload = token.split("\\.")[1];
        assertThrows(JwtVerificationException.class,
                () -> service.verify(noneHeader + "." + payload + "."));
    }

    @Test
    void verify_rejectsExpiredToken() {
        // 签发实例时钟回拨 2 小时（TTL 30 分钟），验签实例正常时钟；同密钥
        JwtService issuer = new JwtService(properties) {
            @Override
            protected long nowMillis() {
                return super.nowMillis() - 2L * 60 * 60 * 1000;
            }
        };
        issuer.init();
        JwtService verifier = new JwtService(properties);
        verifier.init();

        String expired = issuer.issue(1L, "s", "j", TokenType.ACCESS).getToken();
        JwtVerificationException ex = assertThrows(JwtVerificationException.class,
                () -> verifier.verify(expired));
        assertTrue(ex.getMessage().contains("过期"));
    }

    @Test
    void verify_rejectsTokenFromOtherSecret() {
        JwtService a = new JwtService(properties);
        a.init();
        JwtProperties otherProps = new JwtProperties();
        byte[] other = new byte[32];
        other[0] = 9;
        otherProps.setSecret(Base64.getEncoder().encodeToString(other));
        JwtService b = new JwtService(otherProps);
        b.init();

        String token = a.issue(1L, "s", "j", TokenType.ACCESS).getToken();
        assertThrows(JwtVerificationException.class, () -> b.verify(token));
    }

    @Test
    void issue_claimsContainNoSensitivePlainText() {
        JwtService service = new JwtService(properties);
        service.init();
        String token = service.issue(1L, "s", "j", TokenType.REFRESH).getToken();
        String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
        // 令牌里只有定位信息，没有用户名/姓名等敏感明文
        assertFalse(payload.contains("username"));
        assertFalse(payload.contains("admin"));
        assertTrue(payload.contains("\"typ\":\"refresh\""));
    }

    @Test
    void verify_rejectsWrongShapeToken() {
        JwtService service = new JwtService(properties);
        service.init();
        assertThrows(JwtVerificationException.class, () -> service.verify("not-a-jwt"));
        assertThrows(JwtVerificationException.class, () -> service.verify(""));
        assertThrows(JwtVerificationException.class, () -> service.verify(null));
    }

    @Test
    void init_rejectsShortSecret() {
        JwtProperties weak = new JwtProperties();
        weak.setSecret(Base64.getEncoder().encodeToString(new byte[8]));
        JwtService service = new JwtService(weak);
        assertThrows(IllegalStateException.class, service::init);
    }
}
