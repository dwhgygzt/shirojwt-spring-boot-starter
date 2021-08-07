package org.guzt.starter.shirojwt.component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

/**
 * token 缓存接口
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class MyCacheService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * 将对象放入缓存
     *
     * @param key        存储的key，这里一律String 类型
     * @param value      存储对象
     * @param timeToLive 存活时间
     * @param timeUnit   时间单位
     * @param <T>        value的类型
     */
    <T> void setObject(String key, T value, Long timeToLive, TimeUnit timeUnit) {
        logger.info("请覆盖此方法");
    }

    /**
     * 从缓存中获取对象
     *
     * @param key 存储的key，这里一律String 类型
     * @return 具体对象
     */
    Object getObject(String key) {
        logger.info("请覆盖此方法");
        return null;
    }

    /**
     * 从缓存中删除对象
     *
     * @param key 存储的key，这里一律String 类型
     */
    void removeObject(String key) {
        logger.info("请覆盖此方法");
    }


}
