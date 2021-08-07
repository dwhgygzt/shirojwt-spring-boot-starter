package org.guzt.starter.shirojwt.component;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.guzt.starter.shirojwt.context.JwtTokenCacheContext;
import org.guzt.starter.shirojwt.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Cache
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtShiroCache<K, V> implements Cache<K, V> {


    private static Logger logger = LoggerFactory.getLogger(JwtShiroCache.class);

    private MyCacheService myCacheService;

    public JwtShiroCache(MyCacheService myCacheService) {
        this.myCacheService = myCacheService;
    }

    /**
     * 获取当前线程中 jwt 的剩余存活毫秒
     *
     * @return jwt 的剩余存活毫秒
     */
    private Long getTokenRemainMillisecond() {
        String token = JwtTokenCacheContext.getCurrentJwtToken();
        Long remainMillisecond = JwtUtil.getRemainMillisecond(token);
        logger.debug("【ShiroJWT】get Token from JwtTokenContext, token={}, remainMillisecond = {}", token, remainMillisecond);
        return remainMillisecond;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Object get(Object k) throws CacheException {
        logger.debug("【ShiroJWT】get cache k={}", k);
        return myCacheService.getObject(k.toString());
    }

    @Override
    public V put(K k, V v) throws CacheException {
        logger.debug("【ShiroJWT】put cache k={}, v={}", k, v);
        myCacheService.setObject(k.toString(), v, getTokenRemainMillisecond(), TimeUnit.MILLISECONDS);
        JwtTokenCacheContext.remove();
        return v;
    }

    @Override
    public V remove(K k) throws CacheException {
        logger.debug("【ShiroJWT】remove cache k={}", k);
        myCacheService.removeObject(k.toString());
        JwtTokenCacheContext.remove();
        return null;
    }

    @Override
    public void clear() throws CacheException {
        // 此方法无需使用
    }

    @Override
    public int size() {
        // 此方法无需使用
        return 0;
    }

    @Override
    public Set<K> keys() {
        // 此方法无需使用
        return null;
    }

    @Override
    public Collection<V> values() {
        // 此方法无需使用
        return null;
    }
}
