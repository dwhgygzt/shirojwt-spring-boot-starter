package org.guzt.starter.shirojwt.config;

import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * LifecycleBeanPostProcessor 相关配置.
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
@Configuration
@ConditionalOnProperty(prefix = "shirojwt", value = "enable", havingValue = "true", matchIfMissing = true)
public class LifecycleAutoConfig {

    private static Logger logger = LoggerFactory.getLogger(LifecycleAutoConfig.class);

    /**
     * 管理shiro一些bean的生命周期.
     * LifecycleBeanPostProcessor将 Initializable 和 Destroyable 的实现类统一在其内部自动
     * 分别调用了Initializable.init()和Destroyable.destroy()方法，从而达到管理shiro bean生命周期的目的
     *
     * @return LifecycleBeanPostProcessor
     */
    @Bean
    @ConditionalOnMissingBean
    public static LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        logger.debug("【ShiroJWT】Bean LifecycleBeanPostProcessor 初始化 ...");
        return new LifecycleBeanPostProcessor();
    }
}
