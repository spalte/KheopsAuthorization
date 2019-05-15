package online.kheops.auth_server.util;

import javax.ws.rs.core.Form;
import javax.ws.rs.core.MultivaluedMap;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;

public enum TokenClientAuthenticationType {

    CLIENT_SECRET_BASIC("client_secret_basic") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form)
                throws TokenAuthenticationException {
            final String encodedAuthorization = headers.getFirst(AUTHORIZATION).substring(6);

            final String decoded;
            try {
                decoded = new String(Base64.getDecoder().decode(encodedAuthorization), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new TokenAuthenticationException("Unable to decode Basic Authorization");
            }
            String[] split = decoded.split(":");
            if (split.length != 2) {
                throw new TokenAuthenticationException("Basic authentication doesn't have a username and password");
            }

            final String clientId = split[0];
            final String clientSecret = split[1];

            return TokenClientAuthenticator.validateClientIDSecret(clientId, clientSecret);
        }
    },

    PRIVATE_KEY_JWT("private_key_jwt") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form)
                throws TokenAuthenticationException {
            return TokenClientAuthenticator.validateJWT(form.asMap().getFirst(CLIENT_ASSERTION));
        }
    },
    PUBLIC("public") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form) {
            return PUBLIC_PRINCIPAL;
        }
    };

    private static final Logger LOG = Logger.getLogger(TokenClientAuthenticationType.class.getName());

    private static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    private static final String CLIENT_ASSERTION = "client_assertion";
    private static final String JWT_BEARER_URN = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final TokenPrincipal PUBLIC_PRINCIPAL = new TokenPrincipal("Public", TokenClientKind.PUBLIC);

    private String schemeString;

    TokenClientAuthenticationType(String schemeString) {
        this.schemeString = schemeString;
    }

    public String getSchemeString() {
        return schemeString;
    }

    public static TokenClientAuthenticationType getTokenClientAuthenticationType(MultivaluedMap<String, String> headers, Form form) throws TokenAuthenticationException
    {
        MultivaluedMap<String, String> formMap = form.asMap();

        if (headers.containsKey(AUTHORIZATION)) {
            if (formMap.containsKey(CLIENT_ASSERTION_TYPE) || formMap.containsKey(CLIENT_ASSERTION)) {
                throw new TokenAuthenticationException("Client assertion and Authorization Header can not both be present");
            }

            List<String> authorizationHeaders = headers.get(AUTHORIZATION);

            if (authorizationHeaders.size() != 1) {
                throw new TokenAuthenticationException("Only one Authorization Header can be present");
            }
            try {
                if (authorizationHeaders.get(0).substring(0, 6).toUpperCase().equals("BASIC ")) {
                    return TokenClientAuthenticationType.CLIENT_SECRET_BASIC;
                }
            } catch (IndexOutOfBoundsException e) {
                LOG.log(WARNING, "not basic authorization", e);
            }
            throw new TokenAuthenticationException("Unknown authorization header type");
        }

        if (formMap.containsKey(CLIENT_ASSERTION_TYPE) || formMap.containsKey(CLIENT_ASSERTION)) {
            List<String> clientAssertionTypes = formMap.get(CLIENT_ASSERTION_TYPE);
            List<String> clientAssertions = formMap.get(CLIENT_ASSERTION);

            if (clientAssertionTypes == null || clientAssertions == null ||
                    clientAssertionTypes.size() != 1 || clientAssertions.size() != 1) {
                throw new TokenAuthenticationException("Only one client assertion can be present");
            }
            if (!clientAssertionTypes.get(0).equals(JWT_BEARER_URN)) {
                throw new TokenAuthenticationException("Unknown client assertion type");
            }
            if (clientAssertions.get(0).startsWith("eyJ")) {
                return TokenClientAuthenticationType.PRIVATE_KEY_JWT;
            }
        }

        return TokenClientAuthenticationType.PUBLIC;
    }

    public abstract TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form) throws TokenAuthenticationException;
}
