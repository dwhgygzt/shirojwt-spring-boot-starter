package org.guzt.starter.shirojwt.filter;

import org.guzt.starter.shirojwt.config.ShiroJwtAutoConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import java.util.LinkedHashMap;

/**
 * FilterRule
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class ExtraFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 设置额外的过滤器.
     *
     * @param filterMap 已经初始化后的LinkedHashMap
     * @see ShiroJwtAutoConfig#shiroFilterFactoryBean
     */
    public void setExtraFilter(LinkedHashMap<String, Filter> filterMap) {
        if (logger.isDebugEnabled()){
            logger.debug("【ShiroJWT】ShiroFilterFactoryBean 无其他额外 filter 添加，默认过滤器数量{}",filterMap.size());
        }
    }

}
