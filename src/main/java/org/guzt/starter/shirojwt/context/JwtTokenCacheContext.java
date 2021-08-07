package org.guzt.starter.shirojwt.context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JwtToken 上下文，用于特殊途径.
 * 必须是同一个线程里面才能执行 get 方法 !!!!!!!!
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtTokenCacheContext implements AutoCloseable {

    private static Logger logger = LoggerFactory.getLogger(JwtTokenCacheContext.class);

    /**
     * ThreadLocal 对象
     */
    static final ThreadLocal<String> CURRENT_JWT_TOKEN = new ThreadLocal<>();

    public static void setCurrentJwtToken(String token) {
        CURRENT_JWT_TOKEN.set(token);
    }

    /**
     * 必须是同一个线程里面才有可能能 get到对象，前提是你必须之前set过
     *
     * @return CurrentUserVO
     */
    public static String getCurrentJwtToken() {
        return CURRENT_JWT_TOKEN.get();
    }

    public static void remove() {
        CURRENT_JWT_TOKEN.remove();
        if (logger.isDebugEnabled()) {
            logger.debug("JwtTokenContext remove...");
        }
    }

    /**
     * 一般是 借助try (resource) {...}结构.
     * <p>
     * try (var ctx = new UserContext("Bob")) {
     * // 可任意调用 UserContext.currentUser():
     * String currentUser = UserContext.currentUser();
     * }  // 在此自动调用 UserContext.close() 方法释放ThreadLocal关联对象
     */
    @Override
    public void close() {
        CURRENT_JWT_TOKEN.remove();
    }
}

