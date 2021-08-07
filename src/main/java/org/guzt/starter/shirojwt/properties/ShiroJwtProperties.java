package org.guzt.starter.shirojwt.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * shiro jwt 配置文件
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
@ConfigurationProperties(prefix = "shirojwt")
public class ShiroJwtProperties {

    /**
     * 登录路径 默认 /api/login
     */
    private String loginUrl = "/api/login";

    /**
     * 登出路径 默认 /api/logout
     */
    private String logoutUrl = "/api/logout";

    /**
     * JWTtoken 过期秒数
     */
    private Integer tokenExpireSeconds = 60 * 60;

    /**
     * JWTtoken 刷新秒数，表示 是否已经发布了 tokenRefreshSeconds 秒，如果超过就刷新一个新的token给前端
     */
    private Integer tokenRefreshSeconds = 40 * 60;

    /**
     * 是否开启 本地缓存 CacheManager 默认不开启
     */
    private boolean enableCacheManager = false;

    /**
     * JWT 的签发者 默认为 无
     */
    private String jwtIssuer = "";

    /**
     * JWT 的主题 默认为 jwtAuthToken
     */
    private String jwtSubject = "";

    /**
     * 是否启用ShiroJwt true 启用  false 禁用
     */
    private boolean enable = true;

    /**
     * token放在 http HEADER 里面的 key名称，默认为 Authorization
     */
    private String tokenHeaderKey = "Authorization";

    /**
     * 是否支持跨域访问 默认为 true
     */
    private boolean corsEnable = true;

    /**
     * 是否启用 token 自动刷新
     */
    private boolean tokenRefreshEnable = true;

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public void setLogoutUrl(String logoutUrl) {
        this.logoutUrl = logoutUrl;
    }

    public Integer getTokenExpireSeconds() {
        return tokenExpireSeconds;
    }

    public void setTokenExpireSeconds(Integer tokenExpireSeconds) {
        this.tokenExpireSeconds = tokenExpireSeconds;
    }

    public Integer getTokenRefreshSeconds() {
        return tokenRefreshSeconds;
    }

    public void setTokenRefreshSeconds(Integer tokenRefreshSeconds) {
        this.tokenRefreshSeconds = tokenRefreshSeconds;
    }

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public boolean isEnableCacheManager() {
        return enableCacheManager;
    }

    public void setEnableCacheManager(boolean enableCacheManager) {
        this.enableCacheManager = enableCacheManager;
    }

    public String getTokenHeaderKey() {
        return tokenHeaderKey;
    }

    public void setTokenHeaderKey(String tokenHeaderKey) {
        this.tokenHeaderKey = tokenHeaderKey;
    }

    public String getJwtIssuer() {
        return jwtIssuer;
    }

    public void setJwtIssuer(String jwtIssuer) {
        this.jwtIssuer = jwtIssuer;
    }

    public String getJwtSubject() {
        return jwtSubject;
    }

    public void setJwtSubject(String jwtSubject) {
        this.jwtSubject = jwtSubject;
    }

    public boolean isCorsEnable() {
        return corsEnable;
    }

    public void setCorsEnable(boolean corsEnable) {
        this.corsEnable = corsEnable;
    }

    public boolean isTokenRefreshEnable() {
        return tokenRefreshEnable;
    }

    public void setTokenRefreshEnable(boolean tokenRefreshEnable) {
        this.tokenRefreshEnable = tokenRefreshEnable;
    }
}
