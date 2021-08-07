package org.guzt.starter.shirojwt.filter;

import org.guzt.starter.shirojwt.component.JwtBussinessService;
import org.guzt.starter.shirojwt.context.JwtTokenCacheContext;
import org.guzt.starter.shirojwt.context.ShiroExceptionContext;
import org.guzt.starter.shirojwt.exception.NoTokenAuthenticationException;
import org.guzt.starter.shirojwt.exception.ProgramErrorAuthenticationException;
import org.guzt.starter.shirojwt.properties.ShiroJwtProperties;
import org.guzt.starter.shirojwt.token.JwtToken;
import org.guzt.starter.shirojwt.util.FilterUtil;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JwtFilter
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtFilter extends BasicHttpAuthenticationFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private static ShiroJwtProperties shiroJwtProperties;

    private static JwtBussinessService jwtBussinessService;

    public static void setShiroJwtProperties(ShiroJwtProperties shiroJwtProperties) {
        JwtFilter.shiroJwtProperties = shiroJwtProperties;
    }

    public static void setJwtBussinessService(JwtBussinessService jwtBussinessService) {
        JwtFilter.jwtBussinessService = jwtBussinessService;
    }

    /**
     * 再执行判断之前统一处理跨域问题
     *
     * @param request  ignore
     * @param response ignore
     * @return ignore
     * @throws Exception ignore
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        if (shiroJwtProperties.isCorsEnable()) {
            // 跨域提供支持
            FilterUtil.crossDomainPreHandle(request, response);
            // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
            if (RequestMethod.OPTIONS.name().equals(WebUtils.toHttp(request).getMethod())) {
                // 将不再执行后面的过滤器
                return Boolean.FALSE;
            }
        }

        return super.preHandle(request, response);
    }

    /**
     * 检测Header里 Authorization 字段
     *
     * @param request  ServletRequest
     * @param response ServletResponse
     * @return true 包含token fase 不包含token
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest req = WebUtils.toHttp(request);
        String token = req.getHeader(shiroJwtProperties.getTokenHeaderKey());
        return StringUtils.hasText(token);
    }

    /**
     * 构建JWTtoken 用于执行 executeLogin时传入
     *
     * @param servletRequest  ServletRequest
     * @param servletResponse ServletResponse
     * @return JwtToken
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest servletRequest, ServletResponse servletResponse) {
        HttpServletRequest req = WebUtils.toHttp(servletRequest);
        String token = req.getHeader(shiroJwtProperties.getTokenHeaderKey());
        if (StringUtils.hasText(token)) {
            return new JwtToken(token);
        } else {
            // 返回null的话会直接抛出异常，进入isAccessAllowed（）的异常处理逻辑
            // 直接返回空串 验证不通过
            return new JwtToken(StringUtils.EMPTY_STRING);
        }
    }

    /**
     * 根据jwtToken 判断是否可以访问后台接口
     *
     * @param request     ignore
     * @param response    ignore
     * @param mappedValue 访问的URL
     * @return true token验证通过  fasle token验证失败
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        boolean allowed = false;
        // 访问必须带有 Header参数 Authorization
        if (!this.isLoginAttempt(request, response)) {
            // isPermissive(mappedValue)做用户认证，permissive参数的作用是当token无效时也允许请求访问，不会返回鉴权未通过的错误
            // 例如 路径拦截那边设置 ("/logout", "noSessionCreation,jwt[permissive]"); 用户要登出即使token不正确也可访问登出接口
            allowed = super.isPermissive(mappedValue);
            if (!allowed) {
                ShiroExceptionContext.setCurrentException(new NoTokenAuthenticationException("the authToken is null"));
            }
            return allowed;
        }

        String url = WebUtils.toHttp(request).getRequestURI();
        if (logger.isDebugEnabled()) {
            logger.debug("JwtFilter isAccessAllowed url:{}", url);
        }

        try {
            // 进行认证操作，会执行 JwtRealm里面的 doGetAuthenticationInfo 方法
            allowed = executeLogin(request, response);
        } catch (Exception e) {
            ShiroExceptionContext.setCurrentException(new ProgramErrorAuthenticationException("JwtFilter isAccessAllowed Exception"));
            logger.error("JwtFilter isAccessAllowed 异常", e);
        }

        return allowed || super.isPermissive(mappedValue);
    }

    /**
     * 认证失败时候执行的方法.
     *
     * @param servletRequest  ignore
     * @param servletResponse ignore
     * @return true 将继续执行后面过滤器，false 将不再执行后面的过滤器
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) {
        if (logger.isDebugEnabled()) {
            logger.debug("认证失败, 执行onAccessDenied 方法...");
        }
        try {
            jwtBussinessService.onAccessDenied(
                    WebUtils.toHttp(servletRequest),
                    WebUtils.toHttp(servletResponse),
                    isLoginAttempt(servletRequest, servletResponse),
                    ShiroExceptionContext.getCurrentException());
        } catch (IOException ioe) {
            logger.error("JwtFilter onAccessDenied IOException", ioe);
        } finally {
            ShiroExceptionContext.remove();
            JwtTokenCacheContext.remove();
        }

        return Boolean.FALSE;
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) {
        ShiroExceptionContext.remove();
        JwtTokenCacheContext.remove();
        if (token instanceof JwtToken) {
            HttpServletResponse httpResponse = WebUtils.toHttp(response);
            String oldToken = (String) token.getPrincipal();
            String resultToken = oldToken;
            if (shiroJwtProperties.isTokenRefreshEnable() && FilterUtil.shouldTokenRefresh(oldToken)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("old token {}", oldToken);
                }

                // 重新生成一个新的 jwtToken
                resultToken = jwtBussinessService.refreshOldToken(oldToken);
                httpResponse.setStatus(HttpStatus.CREATED.value());
                httpResponse.setHeader(shiroJwtProperties.getTokenHeaderKey(), resultToken);
                // 头部属性 SysConstants.AUTH_TOKEN 可以作为响应的一部分暴露给外部
                httpResponse.setHeader("Access-Control-Expose-Headers", shiroJwtProperties.getTokenHeaderKey());
                if (logger.isDebugEnabled()) {
                    logger.debug("刷新后新的Token {}", resultToken);
                }
            }

            jwtBussinessService.onLoginSuccess(resultToken);

        }

        return Boolean.TRUE;
    }

    /**
     * 为什么不再这里面执行错误信息返回，主要考虑可能发生非AuthenticationToken异常的情况，所以在 onAccessDenied 方法里面执行认证失败信息返回。
     *
     * @param token    AuthenticationToken
     * @param e        AuthenticationException
     * @param request  ServletRequest
     * @param response ServletResponse
     * @return boolean
     * @see org.apache.shiro.web.filter.authc.AuthenticatingFilter#executeLogin(ServletRequest, ServletResponse)
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        if (logger.isDebugEnabled()) {
            logger.debug("认证失败 执行onLoginFailure 方法... errorMsg = {}", e.getMessage());
        }

        ShiroExceptionContext.setCurrentException(e);
        return super.onLoginFailure(token, e, request, response);
    }
}

