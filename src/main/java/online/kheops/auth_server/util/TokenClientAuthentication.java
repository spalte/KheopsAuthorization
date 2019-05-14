package online.kheops.auth_server.util;

import javax.ws.rs.core.Form;
import javax.ws.rs.core.MultivaluedMap;
import java.util.List;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;

public enum TokenClientAuthentication {

    CLIENT_SECRET_BASIC("client_secret_basic") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form) {
            // get and parse the header
            // set the username to DICOMWEB proxy or KheopsZipper as appropriate

            return new TokenPrincipal("DICOMWEBPRoxy or ZIPPer", TokenClientKind.INTERNAL);
        }
    },

    PRIVATE_KEY_JWT("private_key_jwt") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form) {
            // get the configuration URI

            // parse and verify the assertion
            return new TokenPrincipal("Sub from the token", TokenClientKind.REPORT_PROVIDER);
        }
    },
    NONE("none") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form) {
            return NONE_PRINCIPAL;
        }
    },
    INVALID("invalid") {
        public TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form) {
            throw new IllegalStateException("can't get a Principle for an invalid authentication type");
        }
    };

    private static final Logger LOG = Logger.getLogger(TokenClientAuthentication.class.getName());

    private static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    private static final String CLIENT_ASSERTION = "client_assertion";
    private static final String JWT_BEARER_URN = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final TokenPrincipal NONE_PRINCIPAL = new TokenPrincipal("Public", TokenClientKind.PUBLIC);

    private String schemeString;

    TokenClientAuthentication(String schemeString) {
        this.schemeString = schemeString;
    }

    public String getSchemeString() {
        if (this == INVALID) {
            throw new IllegalStateException("INVALID TokenClientAuthentication does not have a scheme");
        }
        return schemeString;
    }

    public static TokenClientAuthentication getTokenClientAuthentication(MultivaluedMap<String, String> headers, Form form)
    {
        MultivaluedMap<String, String> formMap = form.asMap();

        if (headers.containsKey(AUTHORIZATION)) {
            if (formMap.containsKey(CLIENT_ASSERTION_TYPE) || formMap.containsKey(CLIENT_ASSERTION)) {
                return TokenClientAuthentication.INVALID;
            }

            List<String> authorizationHeaders = headers.get(AUTHORIZATION);

            if (authorizationHeaders.size() != 1) {
                return TokenClientAuthentication.INVALID;
            }
            try {
                if (authorizationHeaders.get(0).substring(0, 7).toUpperCase().equals("BEARER ")) {
                    return TokenClientAuthentication.CLIENT_SECRET_BASIC;
                }
            } catch (IndexOutOfBoundsException e) {
                LOG.log(WARNING, "not bearer authorization", e);
            }
            return TokenClientAuthentication.INVALID;
        }

        if (formMap.containsKey(CLIENT_ASSERTION_TYPE) || formMap.containsKey(CLIENT_ASSERTION)) {
            List<String> clientAssertionTypes = formMap.get(CLIENT_ASSERTION_TYPE);
            List<String> clientAssertions = formMap.get(CLIENT_ASSERTION);

            if (clientAssertionTypes == null || clientAssertions == null ||
                    clientAssertionTypes.size() != 1 || clientAssertions.size() != 1) {
                return TokenClientAuthentication.INVALID;
            }
            if (!clientAssertionTypes.get(0).equals(JWT_BEARER_URN)) {
                return TokenClientAuthentication.INVALID;
            }
            if (clientAssertions.get(0).startsWith("eyJ")) {
                return TokenClientAuthentication.PRIVATE_KEY_JWT;
            }
        }

        return TokenClientAuthentication.NONE;
    }

    public abstract TokenPrincipal getPrincipal(MultivaluedMap<String, String> headers, Form form);
}
