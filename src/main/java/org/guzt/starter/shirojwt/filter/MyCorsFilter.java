package org.guzt.starter.shirojwt.filter;

import org.guzt.starter.shirojwt.util.FilterUtil;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * 对跨域的支持
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class MyCorsFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        return Boolean.TRUE;
    }


    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) {
        // 跨域提供支持
        FilterUtil.crossDomainPreHandle(request, response);
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (RequestMethod.OPTIONS.name().equals(WebUtils.toHttp(request).getMethod())) {
            // 将不再执行后面的过滤器
            return Boolean.FALSE;
        } else {
            return Boolean.TRUE;
        }
    }
}
