package org.guzt.starter.shirojwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.guzt.starter.shirojwt.properties.ShiroJwtProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Jwt 签名，验证，取值工具类
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtUtil {

    private static String tokenExpireSecondsKey = "tokenExpireSeconds";

    private static String tokenRefreshSecondsKey = "tokenRefreshSeconds";

    private static String userNameKey = "userName";

    private static String tenantIdKey = "tenantId";

    private static Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private static ShiroJwtProperties shiroJwtProperties;

    public static void setShiroJwtProperties(ShiroJwtProperties shiroJwtProperties) {
        JwtUtil.shiroJwtProperties = shiroJwtProperties;
    }

    /**
     * 校验token是否正确
     *
     * @param token  密钥
     * @param secret 需要验证的密文，例如加工后的用户密码
     * @param salt   盐值
     * @return 是否正确
     */
    public static boolean verify(String token, String secret, String salt) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(salt + secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(shiroJwtProperties.getJwtIssuer())
                    .withSubject(shiroJwtProperties.getJwtSubject())
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            if (jwt != null) {
                return true;
            }
        } catch (SignatureVerificationException e) {
            logger.debug("Verify Token Exception SignatureVerificationException");
            logger.debug("toke = {}", token);
            logger.debug("salt = {}", salt);
            logger.debug("secret = {}", secret);
        } catch (Exception e) {
            logger.debug("toke = {}", token);
            logger.debug("salt = {}", salt);
            logger.debug("secret = {}", secret);
            logger.error("Verify Token Exception", e);
        }
        return false;
    }


    /**
     * 从token中获取 claim值
     *
     * @return token中包含的 claimValue
     */
    public static String getClaimValue(String token, String claimName) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            Claim claim = jwt.getClaim(claimName);
            if (claim != null) {
                return claim.asString();
            } else {
                return null;
            }
        } catch (JWTDecodeException e) {
            logger.error("getClaimValue(..) JWTDecodeException");
            logger.error("token = {}, claimName={}", token, claimName);
            return null;
        }
    }

    /**
     * 从token中获取 userName, 前提是生成token是携带了key为userName的属性
     *
     * @return token中包含的 claimValue
     */
    public static String getUserName(String token) {
        return getClaimValue(token, userNameKey);
    }

    /**
     * 从token中获取 tenantId, 前提是生成token是携带了key为tenantId的属性
     *
     * @return token中包含的 claimValue
     */
    public static String getTenantId(String token) {
        return getClaimValue(token, tenantIdKey);
    }

    /**
     * 从token中获取 JWT的 签发时间
     *
     * @return JWT的 签发时间
     */
    public static Date getIssuedAt(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getIssuedAt();
        } catch (JWTDecodeException e) {
            logger.error("getIssuedAt(..) JWTDecodeException");
            logger.error("token = {}", token);
            return null;
        }
    }

    /**
     * 从token中获取 JWT的 过期时间
     *
     * @return JWT的 过期时间
     */
    public static Date getExpiresAt(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getExpiresAt();
        } catch (JWTDecodeException e) {
            logger.error("getExpiresAt(..) JWTDecodeException");
            logger.error("token = {}", token);
            return null;
        }
    }

    /**
     * 从token中获取 JWT的 会自动刷新的秒数
     *
     * @return JWT的 会自动刷新的秒数
     */
    public static Integer getTokenRefreshSeconds(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(tokenRefreshSecondsKey).asInt();
        } catch (JWTDecodeException e) {
            logger.error("getTokenExpireSeconds(..) JWTDecodeException");
            logger.error("token = {}", token);
            return null;
        }
    }

    /**
     * 从token中获取 JWT的 过期秒数
     *
     * @return JWT的 过期秒数
     */
    public static Integer getTokenExpireSeconds(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(tokenExpireSecondsKey).asInt();
        } catch (JWTDecodeException e) {
            logger.error("getTokenExpireSeconds(..) JWTDecodeException");
            logger.error("token = {}", token);
            return null;
        }
    }

    /**
     * 生成签名,30min后过期
     *
     * @param claims              附带信息
     * @param secret              用户密码
     * @param salt                盐值 增加用户密码被破解的复杂性
     * @param tokenExpireSeconds  token 过期时间
     * @param tokenRefreshSeconds token 需要刷新时间
     * @return 加密的token
     */
    public static String sign(
            Map<String, String> claims,
            String secret,
            String salt,
            Integer tokenExpireSeconds,
            Integer tokenRefreshSeconds) {
        Date issuedAt = new Date(System.currentTimeMillis());
        Date expiresAt = new Date(System.currentTimeMillis() + tokenExpireSeconds * 1000);
        Algorithm algorithm = Algorithm.HMAC256(salt + secret);

        JWTCreator.Builder jwtBuilder = JWT.create();
        if (claims != null && !claims.isEmpty()) {
            claims.forEach(jwtBuilder::withClaim);
        }
        jwtBuilder.withClaim(tokenExpireSecondsKey, tokenExpireSeconds);
        jwtBuilder.withClaim(tokenRefreshSecondsKey, tokenRefreshSeconds);
        return jwtBuilder.withJWTId(UUID.randomUUID().toString().replaceAll("-", ""))
                .withIssuer(shiroJwtProperties.getJwtIssuer())
                .withSubject(shiroJwtProperties.getJwtSubject())
                .withExpiresAt(expiresAt)
                .withIssuedAt(issuedAt)
                .sign(algorithm);
    }

    /**
     * 生成签名, 默认 60min后过期, 30分钟会自动刷新
     *
     * @param claims 附带信息
     * @param secret 用户密码
     * @param salt   盐值 增加用户密码被破解的复杂性
     * @return 加密的token
     */
    public static String sign(Map<String, String> claims, String secret, String salt) {
        return sign(claims, secret, salt,
                shiroJwtProperties.getTokenExpireSeconds(),
                shiroJwtProperties.getTokenRefreshSeconds());
    }

    /**
     * 生成签名, 默认 60min后过期, 30分钟会自动刷新
     *
     * @param userName 用户唯一标识
     * @param tenantId 用户所属租户 用于多租户系统
     * @param secret   用户密码
     * @param salt     盐值 增加用户密码被破解的复杂性
     * @return 加密的token
     */
    public static String sign(String userName, String tenantId, String secret, String salt) {
        Map<String, String> claims = new HashMap<>(2);
        claims.put(userNameKey, userName);
        claims.put(tenantIdKey, tenantId);
        return sign(claims, secret, salt,
                shiroJwtProperties.getTokenExpireSeconds(),
                shiroJwtProperties.getTokenRefreshSeconds());
    }

    /**
     * 生成签名, 默认 60min后过期, 30分钟会自动刷新
     *
     * @param userName 用户唯一标识
     * @param secret   用户密码
     * @param salt     盐值 增加用户密码被破解的复杂性
     * @return 加密的token
     */
    public static String sign(String userName, String secret, String salt) {
        Map<String, String> claims = new HashMap<>(2);
        claims.put(userNameKey, userName);
        return sign(claims, secret, salt,
                shiroJwtProperties.getTokenExpireSeconds(),
                shiroJwtProperties.getTokenRefreshSeconds());
    }

    /**
     * 生成签名, 默认 60min后过期, 30分钟会自动刷新
     *
     * @param secret 用户密码
     * @param salt   盐值 增加用户密码被破解的复杂性
     * @return 加密的token
     */
    public static String sign(String secret, String salt) {
        return sign(Collections.emptyMap(), secret, salt,
                shiroJwtProperties.getTokenExpireSeconds(),
                shiroJwtProperties.getTokenRefreshSeconds());
    }
}
