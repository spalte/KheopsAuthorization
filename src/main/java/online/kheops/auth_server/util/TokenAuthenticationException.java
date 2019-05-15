package online.kheops.auth_server.util;

public class TokenAuthenticationException extends Exception {
    public TokenAuthenticationException() {
        super();
    }

    public TokenAuthenticationException(String message) {
        super(message);
    }
}
