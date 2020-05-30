package org.guzt.starter.shirojwt.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * JwtToken
 *
 * @author <a href="mailto:guzhongtao@middol.com">guzhongtao</a>
 */
public class JwtToken implements AuthenticationToken {

    /**
     * 密钥
     */
    private String token;

    public JwtToken(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
