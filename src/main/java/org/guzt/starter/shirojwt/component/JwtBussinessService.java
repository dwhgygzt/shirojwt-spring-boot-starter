package org.guzt.starter.shirojwt.component;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;

/**
 * 需要引入该stater模块的业务系统重新的service类 .
 * 业务系统重新该类的方法即可
 * beanName = jwtBussinessService
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtBussinessService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 授权
     * 在hasRole perm[''] 或 @RequiresPermissions('xxx')时调用该方法
     *
     * @param principals 当前认证的对象 即token
     * @param realmName  ignore
     * @return AuthorizationInfo
     */
    public AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals, String realmName) {
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        if (logger.isDebugEnabled()) {
            logger.debug("进入授权 doGetAuthorizationInfo");
            logger.debug("the toke is  {}", principals.toString());
            logger.debug("realmName = {}", realmName);
            logger.debug("你需要重写方法： doGetAuthorizationInfo（PrincipalCollection principals）");
        }
        // 该用户具有哪些权限
        authorizationInfo.addStringPermissions(new HashSet<>());
        // 该用户具有哪些角色
        authorizationInfo.addRoles(new HashSet<>());

        return authorizationInfo;
    }


    /**
     * 认证
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     * 在 subject.login(token) 时调用该方法
     *
     * @param auth      认证令牌
     * @param realmName ignore
     * @return SimpleAuthenticationInfo 认证所需要信息
     * @throws AuthenticationException 认证未通过
     */
    public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken auth, String realmName) throws AuthenticationException {
        // 拿到需要认证的 token
        String token = (String) auth.getCredentials();
        if (logger.isDebugEnabled()) {
            logger.debug("进入认证 doGetAuthenticationInfo");
            logger.debug("the toke is  {}", token);
            logger.debug("你需要重写方法： doGetAuthenticationInfo（AuthenticationToken auth）");
        }
        // 从数据库中获得用户具体的 secret 和 salt
        // 将用户放到登录认证info中，无需自己做密码对比， JwtCredentialsMatcher会进行密码校验
        return new SimpleAuthenticationInfo(token, "secret", ByteSource.Util.bytes("salt"), realmName);
    }

    /**
     * token 校验失败
     *
     * @param request       HttpServletRequest
     * @param response      HttpServletResponse
     * @param isTokenExists boolean true 存在  false 不存在
     */
    public void onAccessDenied(HttpServletRequest request, HttpServletResponse response, boolean isTokenExists) throws IOException {
        onAccessDenied(request, response, isTokenExists, new IncorrectCredentialsException("doGetAuthentication fail"));
    }

    /**
     * token 校验失败
     *
     * @param request       HttpServletRequest
     * @param response      HttpServletResponse
     * @param isTokenExists boolean true 存在  false 不存在
     * @param ex            ShiroException
     */
    public void onAccessDenied(HttpServletRequest request, HttpServletResponse response, boolean isTokenExists, ShiroException ex) throws IOException {
        if (logger.isTraceEnabled()) {
            logger.trace("request url {}", request.getRequestURL());
        }
        String errorMsg;
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        if (!isTokenExists) {
            errorMsg = "token is null";
        } else if (ex != null) {
            errorMsg = ex.getLocalizedMessage();
        } else {
            errorMsg = "doGetAuthentication fail";
        }
        defaultPrintJson(response, "{\"code\":\"-1\",\"data\":{\"bussinessCode\":\"401\"},\"message\":\"" + errorMsg + "\"}");
    }

    /**
     * 直接输出JSON 格式的认证失败信息.
     *
     * @param response HttpServletResponse
     * @param msg      JSON
     * @throws IOException ignore
     */
    public void defaultPrintJson(HttpServletResponse response, String msg) throws IOException {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();
        printWriter.write(msg);
        printWriter.flush();
        printWriter.close();
    }

    /**
     * 刷新token， 如果有 redis缓存记得刷新
     *
     * @param oldToken 需要被刷新的token
     * @return 获得最新的 token
     */
    public String refreshOldToken(String oldToken) {
        if (logger.isDebugEnabled()) {
            logger.debug("被刷新的token {}", oldToken);
            logger.debug("你需要重写方法： refreshOldToken（String oldToken）");
        }

        return "your new token";
    }

}


