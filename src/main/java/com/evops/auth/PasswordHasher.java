package com.evops.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 口令哈希：单用户随机盐 + SHA-256 迭代 1024 轮。
 * 与 t_sys_user.password_hash/salt 对应；库中绝不存明文口令。
 */
public final class PasswordHasher {

    /** 迭代轮数，固定值，变更后旧口令需重置。 */
    public static final int ITERATIONS = 1024;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    /** 生成 16 字节随机盐（小写十六进制）。 */
    public static String randomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return toHex(salt);
    }

    /**
     * 计算哈希：d0 = SHA-256(salt || 明文口令)，之后对摘要本身再迭代 ITERATIONS-1 轮。
     */
    public static String hash(String rawPassword, String saltHex) {
        MessageDigest digest = sha256();
        byte[] d = digest.digest(concat(fromHex(saltHex), rawPassword.getBytes(StandardCharsets.UTF_8)));
        for (int i = 1; i < ITERATIONS; i++) {
            d = digest.digest(d);
        }
        return toHex(d);
    }

    /** 常量时间比较，避免计时侧信道。 */
    public static boolean matches(String rawPassword, String saltHex, String expectedHashHex) {
        if (rawPassword == null || saltHex == null || expectedHashHex == null) {
            return false;
        }
        String actual = hash(rawPassword, saltHex);
        if (actual.length() != expectedHashHex.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < actual.length(); i++) {
            diff |= actual.charAt(i) ^ expectedHashHex.charAt(i);
        }
        return diff == 0;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("当前 JDK 不支持 SHA-256", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("盐值格式不正确");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("盐值格式不正确");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
