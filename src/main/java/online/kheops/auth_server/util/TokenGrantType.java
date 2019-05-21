package online.kheops.auth_server.util;

import javax.servlet.ServletContext;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

public enum TokenGrantType {
    REFRESH_TOKEN("refresh_token") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE);
        }
    },
    AUTHORIZATION_CODE("authorization_code") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            final Principal userPrincipal = securityContext.getUserPrincipal();

            if (!securityContext.isUserInRole(TokenClientKind.REPORT_PROVIDER.getRoleString())) {
                throw new TokenRequestException(TokenRequestException.Error.UNAUTHORIZED_CLIENT);

            }

            if (form.get("code").size() != 1) {
                throw new TokenRequestException(TokenRequestException.Error.INVALID_REQUEST, "Must have a single code");
            }

            // validate the code

            // create an
        }
    },
    PASSWORD("password") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE);
        }
    },
    CLIENT_CREDENTIALS("client_credentials") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE);
        }
    },
    JWT_ASSERTION("urn:ietf:params:oauth:grant-type:jwt-bearer") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE);
        }
    },
    SAML_ASSERTION("urn:ietf:params:oauth:grant-type:saml2-bearer") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE);
        }
    },
    EXCHANGE("urn:ietf:params:oauth:grant-type:token-exchange") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE);
        }
    };

    private final String grantType;

    TokenGrantType(final String grantType) {
        this.grantType = grantType;
    }

    public String toString() {
        return grantType;
    }

    public static TokenGrantType fromString(String grantTypeString) {
        for (TokenGrantType grantType: TokenGrantType.values()) {
            if (grantType.toString().equals(grantTypeString)) {
                return grantType;
            }
        }

        throw new IllegalArgumentException("Unknown grant type");
    }

    public abstract Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form);
}
