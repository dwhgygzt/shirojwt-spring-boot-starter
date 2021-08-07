package org.guzt.starter.shirojwt.config;

import org.guzt.starter.shirojwt.component.JwtBussinessService;
import org.guzt.starter.shirojwt.filter.JwtFilter;
import org.guzt.starter.shirojwt.filter.JwtPermissionsAuthorizationFilter;
import org.guzt.starter.shirojwt.filter.JwtRolesAuthorizationFilter;
import org.guzt.starter.shirojwt.properties.ShiroJwtProperties;
import org.guzt.starter.shirojwt.realm.JwtRealm;
import org.guzt.starter.shirojwt.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.Resource;

/**
 * 一些业务Bean的依赖关系 相关配置.
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
@Configuration
@ConditionalOnProperty(prefix = "shirojwt", value = "enable", havingValue = "true")
public class BussinessBeanDependencyAutoConfig implements InitializingBean {

    private static Logger logger = LoggerFactory.getLogger(BussinessBeanDependencyAutoConfig.class);

    @Resource
    private ApplicationContext applicationContext;

    @Bean
    @ConditionalOnMissingBean
    public JwtBussinessService jwtBussinessService() {
        logger.debug("Bean JwtBussinessService 初始化 ...");
        return new JwtBussinessService();
    }

    @Override
    public void afterPropertiesSet() {
        JwtBussinessService jwtBussinessService = applicationContext.getBean(JwtBussinessService.class);
        ShiroJwtProperties shiroJwtProperties = applicationContext.getBean(ShiroJwtProperties.class);
        JwtRealm jwtRealm = applicationContext.getBean(JwtRealm.class);

        logger.debug("【ShiroJWT】{}装载{}}", jwtRealm.getClass().getSimpleName(), jwtBussinessService.getClass().getSimpleName());
        jwtRealm.setJwtBussinessService(jwtBussinessService);

        logger.debug("【ShiroJWT】JwtFilter装载{})", jwtBussinessService.getClass().getSimpleName());
        JwtFilter.setJwtBussinessService(jwtBussinessService);

        logger.debug("【ShiroJWT】JwtFilter装载{})", shiroJwtProperties.getClass().getSimpleName());
        JwtFilter.setShiroJwtProperties(shiroJwtProperties);

        JwtPermissionsAuthorizationFilter.setJwtBussinessService(jwtBussinessService);
        logger.debug("【ShiroJWT】JwtPermissionsAuthorizationFilter装载{})", jwtBussinessService.getClass().getSimpleName());

        JwtRolesAuthorizationFilter.setJwtBussinessService(jwtBussinessService);
        logger.debug("【ShiroJWT】JwtRolesAuthorizationFilter装载{})", jwtBussinessService.getClass().getSimpleName());

        JwtUtil.setShiroJwtProperties(shiroJwtProperties);
        logger.debug("【ShiroJWT】JwtUtil装载{})", shiroJwtProperties.getClass().getSimpleName());
    }
}
