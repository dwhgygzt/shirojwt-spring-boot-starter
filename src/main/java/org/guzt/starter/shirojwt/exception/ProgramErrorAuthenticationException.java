package org.guzt.starter.shirojwt.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 * 认证程序执行异常
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class ProgramErrorAuthenticationException extends AuthenticationException {
    /**
     * Creates a new AccountException.
     */
    public ProgramErrorAuthenticationException() {
        super();
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     */
    public ProgramErrorAuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ProgramErrorAuthenticationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ProgramErrorAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
