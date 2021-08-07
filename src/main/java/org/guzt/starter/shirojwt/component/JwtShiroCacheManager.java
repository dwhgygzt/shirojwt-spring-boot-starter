package org.guzt.starter.shirojwt.component;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;


/**
 * CacheManager
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtShiroCacheManager implements CacheManager {

    private MyCacheService myCacheService;

    public JwtShiroCacheManager(MyCacheService myCacheService) {
        this.myCacheService = myCacheService;
    }

    @Override
    public <K, V> Cache<K, V> getCache(String s) throws CacheException {
        return new JwtShiroCache<>(myCacheService);
    }
}
