package online.kheops.auth_server.util;

import javax.servlet.ServletContext;
import java.util.Objects;

public final class TokenBasicAuthenticator {

    private static final String DICOMWEB_PROXY_CLIENT_ID = "DICOMwebProxy";
    private static final String DICOMWEB_PROXY_CLIENT_SECRET_PARAMETER = "online.kheops.client.dicomwebproxysecret";
    private static final String ZIPPER_CLIENT_ID = "Zipper";
    private static final String ZIPPER_CLIENT_SECRET_PARAMETER = "online.kheops.client.zippersecret";

    private enum KnownClients {
        DICOMWEB_PROXY(DICOMWEB_PROXY_CLIENT_ID, DICOMWEB_PROXY_CLIENT_SECRET_PARAMETER),
        ZIPPER(ZIPPER_CLIENT_ID, ZIPPER_CLIENT_SECRET_PARAMETER);

        private String clientId;
        private String passwordParameter;

        KnownClients(String clientId, String passwordParameter) {
            this.clientId = clientId;
            this.passwordParameter = passwordParameter;
        }

        public String getClientId() {
            return clientId;
        }

        public String getPassword(ServletContext context) {
            return context.getInitParameter(passwordParameter);
        }
    }

    final private ServletContext context;
    private String clientId;
    private String password;

    public static TokenBasicAuthenticator newAuthenticator(final ServletContext context) {
        return new TokenBasicAuthenticator(context);
    }

    private TokenBasicAuthenticator(final ServletContext context) {
        this.context = context;
    }

    public TokenBasicAuthenticator clientId(final String clientId) {
        this.clientId = Objects.requireNonNull(clientId);
        return this;
    }

    public TokenBasicAuthenticator password(final String password) {
        this.password = Objects.requireNonNull(password);
        return this;
    }

    public TokenPrincipal authenticate() throws TokenAuthenticationException {
        Objects.requireNonNull(clientId);
        Objects.requireNonNull(password);

        for (KnownClients client: KnownClients.values()) {
            final String name = client.getClientId();
            if (client.getPassword(context).equals(password)) {
                return new TokenPrincipal() {
                    @Override
                    public TokenClientKind getClientKind() {
                        return TokenClientKind.INTERNAL;
                    }

                    @Override
                    public String getName() {
                        return name;
                    }
                };
            }
        }

        throw new TokenAuthenticationException("unable to authenticate clientId: " + clientId);
    }
}
