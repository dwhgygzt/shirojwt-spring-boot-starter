package org.guzt.starter.shirojwt.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;

/**
 * FilterRule
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class ExtraFilterRule {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 设置额外的路径规则 map 已经存在可以修改里面的值.
     * <p>
     * 最后无需添加 "/**", "noSessionCreation,jwt" 已经默认加上
     *
     * @param filterRuleMap 已经初始化后的LinkedHashMap
     * @see org.guzt.starter.shirojwt.config.ShiroJwtAutoConfig#shiroFilterFactoryBean
     */
    public void setExtraFilterRule(LinkedHashMap<String, String> filterRuleMap) {
        if (logger.isDebugEnabled()){
            logger.debug("【ShiroJWT】jwtFilter 无额外的路径规则设置, 默认规则数 {}",filterRuleMap.size());
        }
    }

}
