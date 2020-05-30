package org.guzt.starter.shirojwt.realm;

import org.guzt.starter.shirojwt.component.JwtBussinessService;
import org.guzt.starter.shirojwt.token.JwtToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * AuthorizingRealm
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtRealm extends AuthorizingRealm {

    private JwtBussinessService jwtBussinessService;

    public void setJwtBussinessService(JwtBussinessService jwtBussinessService) {
        this.jwtBussinessService = jwtBussinessService;
    }

    /**
     * 限定这个Realm只支持自定义的JwtToken.
     * 必须重写该方法，表示token类型是JwtToken的才会进入该 Realm里面
     * 执行doGetAuthorizationInfo 或 doGetAuthenticationInfo方法
     *
     * @param token AuthenticationToken
     * @return true MyRealm支持本次验证  fase 直接跳过不支持本次验证
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    /**
     * 授权
     * 在hasRole perm[''] 或 @RequiresPermissions('xxx')时调用该方法
     *
     * @param principals 当前认证的对象 即token
     * @return AuthorizationInfo
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return jwtBussinessService.doGetAuthorizationInfo(principals, getName());
    }


    /**
     * 认证
     * 默认使用此方法进行用户名正确与否验证，错误抛出异常即可。
     * 在 subject.login(token) 时调用该方法
     *
     * @param auth 认证令牌
     * @return SimpleAuthenticationInfo 认证所需要信息
     * @throws AuthenticationException 认证未通过
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken auth) throws AuthenticationException {
        return jwtBussinessService.doGetAuthenticationInfo(auth, getName());
    }
}
