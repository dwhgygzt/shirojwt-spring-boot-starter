package org.guzt.starter.shirojwt.util;

import org.apache.shiro.web.util.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * 过滤器公共方法
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class FilterUtil {

    /**
     * 跨域的支持
     *
     * @param request  ServletRequest
     * @param response ServletResponse
     */
    public static void crossDomainPreHandle(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
        // 标识允许哪个域到请求，直接修改成请求头的域
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        // 标识允许的请求方法
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Credentials", "true");
        // 响应首部 Access-Control-Allow-Headers 用于 preflight request （预检请求）中，列出了将会在正式请求的 Access-Control-Expose-Headers 字段中出现的首部信息。修改为请求首部
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (RequestMethod.OPTIONS.name().equals(httpServletRequest.getMethod())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
        }
    }

    /**
     * 根据token发布时间判断，是否已经发布了 TokenRefreshSeconds 秒，如果超过就刷新
     *
     * @param oldToken jwtToken
     * @return true 需要刷新  false 不需要
     */
    public static boolean shouldTokenRefresh(String oldToken) {
        // 获取 jwtToken 签发时间
        Date issueAt = JwtUtil.getIssuedAt(oldToken);
        if (issueAt == null) {
            return Boolean.FALSE;
        }
        Integer refreshSeconds = JwtUtil.getTokenRefreshSeconds(oldToken);
        if (refreshSeconds == null){
            return Boolean.FALSE;
        }

        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        // （当前时间 回退 refreshSeconds秒） 比较  issueAt 是否在 issueAt之后, 如果是则需要刷新
        return LocalDateTime.now().minusSeconds(refreshSeconds).isAfter(issueTime);
    }

}
