package org.guzt.starter.shirojwt.context;

import org.apache.shiro.ShiroException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 认证失败的异常信息上下文.
 * 必须是同一个线程里面才能执行 get 方法 !!!!!!!!
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class ShiroExceptionContext implements AutoCloseable {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * ThreadLocal 对象
     */
    static final ThreadLocal<ShiroException> CURRENT_EXCEPTION = new ThreadLocal<>();

    public ShiroExceptionContext() {
        super();
    }

    public ShiroExceptionContext(ShiroException e) {
        CURRENT_EXCEPTION.set(e);
    }

    public static void setCurrentException(ShiroException e) {
        CURRENT_EXCEPTION.set(e);
    }

    /**
     * 必须是同一个线程里面才有可能能 get到对象，前提是你必须之前set过
     *
     * @return CurrentUserVO
     */
    public static ShiroException getCurrentException() {
        return CURRENT_EXCEPTION.get();
    }

    public static void remove() {
        CURRENT_EXCEPTION.remove();
    }

    /**
     * 一般是 借助try (resource) {...}结构.
     * <p>
     * try (var ctx = new UserContext("Bob")) {
     * // 可任意调用 UserContext.currentUser():
     * String currentUser = UserContext.currentUser();
     * }  // 在此自动调用 UserContext.close() 方法释放ThreadLocal关联对象
     *
     * @throws Exception ignore
     */
    @Override
    public void close() throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug("AuthenticationExceptionContext remove...");
        }
        CURRENT_EXCEPTION.remove();
    }
}

