package org.guzt.starter.shirojwt.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 * 没有token异常
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class NoTokenAuthenticationException extends AuthenticationException {
    /**
     * Creates a new AccountException.
     */
    public NoTokenAuthenticationException() {
        super();
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     */
    public NoTokenAuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public NoTokenAuthenticationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new AccountException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public NoTokenAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
