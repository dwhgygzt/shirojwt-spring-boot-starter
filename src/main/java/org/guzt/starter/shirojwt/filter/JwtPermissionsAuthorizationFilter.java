package org.guzt.starter.shirojwt.filter;

import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.guzt.starter.shirojwt.component.JwtBussinessService;
import org.guzt.starter.shirojwt.context.ShiroExceptionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * JwtPermissionsAuthorizationFilter
 *
 * @author admin
 */
public class JwtPermissionsAuthorizationFilter extends PermissionsAuthorizationFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private static JwtBussinessService jwtBussinessService;

    public static void setJwtBussinessService(JwtBussinessService jwtBussinessService) {
        JwtPermissionsAuthorizationFilter.jwtBussinessService = jwtBussinessService;
    }

    @Override
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws IOException {
        boolean allowed = super.isAccessAllowed(request, response, mappedValue);
        if (! allowed){
            ShiroExceptionContext.setCurrentException(new UnauthorizedException("Subject does not have permission" + Arrays.toString(((String[]) mappedValue))));
        }

        return allowed;
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
            logger.debug("权限检查失败, 执行onAccessDenied 方法...");
        }
        try {
            jwtBussinessService.onAccessDenied(
                    WebUtils.toHttp(servletRequest),
                    WebUtils.toHttp(servletResponse),
                    Boolean.TRUE,
                    ShiroExceptionContext.getCurrentException());
        } catch (IOException ioe) {
            logger.error("JwtPermissionsAuthorizationFilter onAccessDenied IOException", ioe);
        } finally {
            ShiroExceptionContext.remove();
        }
        return Boolean.FALSE;
    }
}
