package org.guzt.starter.shirojwt.config;

import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.guzt.starter.shirojwt.component.JwtCredentialsMatcher;
import org.guzt.starter.shirojwt.filter.*;
import org.guzt.starter.shirojwt.properties.ShiroJwtProperties;
import org.guzt.starter.shirojwt.realm.JwtRealm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.Resource;
import javax.servlet.Filter;
import java.util.LinkedHashMap;

/**
 * ShiroJwt 相关配置
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
@Configuration
@EnableConfigurationProperties({ShiroJwtProperties.class})
@ConditionalOnProperty(prefix = "shirojwt", value = "enable", havingValue = "true", matchIfMissing = true)
public class ShiroJwtAutoConfig {

    private static Logger logger = LoggerFactory.getLogger(ShiroJwtAutoConfig.class);

    @Resource
    private ShiroJwtProperties shiroJwtProperties;

    @Resource
    private ExtraFilter extraFilter;

    @Resource
    private ExtraFilterRule extraFilterRule;

    @Bean
    @ConditionalOnMissingBean
    public ExtraFilter extraFilter() {
        return new ExtraFilter();
    }

    @Bean
    @ConditionalOnMissingBean
    public ExtraFilterRule extraFilterRule() {
        return new ExtraFilterRule();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtRealm jwtRealm() {
        logger.debug("【ShiroJWT】Bean JwtRealm 初始化 ...");
        JwtRealm jwtRealm = new JwtRealm();
        jwtRealm.setCredentialsMatcher(new JwtCredentialsMatcher());

        if (shiroJwtProperties.isEnableCacheMemory()) {
            // 使用默认提供的 MemoryConstrainedCacheManager
            jwtRealm.setCacheManager(new MemoryConstrainedCacheManager());
            // 启用身份验证缓存，即缓存AuthenticationInfo信息，默认false
            jwtRealm.setAuthenticationCachingEnabled(true);
            // 启用授权缓存，即缓存AuthorizationInfo信息，默认false,一旦配置了缓存管理器，授权缓存默认开启
            jwtRealm.setAuthorizationCachingEnabled(true);
        }

        return jwtRealm;
    }

    @Bean
    @ConditionalOnMissingBean
    public DefaultWebSecurityManager securityManager(JwtRealm jwtRealm) {
        logger.debug("【ShiroJWT】Bean SecurityManager 初始化 ...");
        // 交由DefaultWebSecurityManager管理
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(jwtRealm);

        /*
         * 使用JWT方式进行访问控制，因此关闭 shiro 自带的 session管理，详情见文档
         * http://shiro.apache.org/session-management.html#SessionManagement-StatelessApplications%28Sessionless%29
         */
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        manager.setSubjectDAO(subjectDAO);

        // 禁用remberMe功能
        manager.setRememberMeManager(null);
        return manager;
    }

    @Bean
    @ConditionalOnMissingBean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(
            DefaultWebSecurityManager securityManager) {
        logger.debug("【ShiroJWT】Bean ShiroFilterFactoryBean 初始化 ...");

        ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
        factoryBean.setSecurityManager(securityManager);

        // 添加自己的过滤器并且取名为jwt
        LinkedHashMap<String, Filter> filterMap = new LinkedHashMap<>(2);
        filterMap.put("jwt", new JwtFilter());
        filterMap.put("myCorsFilter", new MyCorsFilter());
        filterMap.put("jwtPerms", new JwtPermissionsAuthorizationFilter());
        filterMap.put("jwtRoles", new JwtRolesAuthorizationFilter());

        // 设置额外的过滤器
        extraFilter.setExtraFilter(filterMap);
        factoryBean.setFilters(filterMap);

        //路径拦截设置，注意put进去的顺序，放在最前面的先生效！
        LinkedHashMap<String, String> filterRuleMap = new LinkedHashMap<>(32);
        String comma = ",";
        String swaggerUrls = "/swagger-ui.html,/swagger-resources/**,/webjars/**,/v2/api-docs";
        for (String item : swaggerUrls.split(comma)) {
            filterRuleMap.put(item.trim(), "noSessionCreation,anon");
        }
        String bootAdminUrls = "/favicon.ico,/actuator/**,/instances/**,/assets/**,/sba-settings.js,/applications/**";
        for (String item : bootAdminUrls.split(comma)) {
            filterRuleMap.put(item.trim(), "noSessionCreation,anon");
        }
        filterRuleMap.put("/static/**", "noSessionCreation,anon");
        filterRuleMap.put("/templates/**", "noSessionCreation,anon");

        if (shiroJwtProperties.isCorsEnable()) {
            filterRuleMap.put(shiroJwtProperties.getLogoutUrl(), "noSessionCreation,myCorsFilter,jwt[permissive]");
            filterRuleMap.put(shiroJwtProperties.getLoginUrl(), "noSessionCreation,myCorsFilter,anon");
        } else {
            filterRuleMap.put(shiroJwtProperties.getLogoutUrl(), "noSessionCreation,jwt[permissive]");
            filterRuleMap.put(shiroJwtProperties.getLoginUrl(), "noSessionCreation,anon");
        }

        // 其他自定义路径
        extraFilterRule.setExtraFilterRule(filterRuleMap);
        // 其他默认全部jwt验证
        filterRuleMap.put("/**", "noSessionCreation,jwt");

        factoryBean.setFilterChainDefinitionMap(filterRuleMap);
        return factoryBean;
    }

    /**
     * 开启shiro注解支持，例如 @RequiresPermissions
     *
     * @param securityManager DefaultWebSecurityManager
     * @return AuthorizationAttributeSourceAdvisor
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);

        logger.debug("【ShiroJWT】Bean AuthorizationAttributeSourceAdvisor 初始化...");
        return advisor;
    }

}
