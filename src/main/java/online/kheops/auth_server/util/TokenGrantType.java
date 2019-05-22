package online.kheops.auth_server.util;

import javax.servlet.ServletContext;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static online.kheops.auth_server.util.TokenRequestException.Error.*;

public enum TokenGrantType {
    REFRESH_TOKEN("refresh_token") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(UNSUPPORTED_GRANT_TYPE);
        }
    },
    AUTHORIZATION_CODE("authorization_code") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            verifySingle(form, "code");
            verifySingle(form, "client_id");

            final String clientId = form.getFirst("client_id");
            final String code = form.getFirst("code");

            if (!securityContext.isUserInRole(TokenClientKind.REPORT_PROVIDER.getRoleString())) {
                throw new TokenRequestException(UNAUTHORIZED_CLIENT);
            }

            final DecodedAuthorizationCode authorizationCode;
            try {
                authorizationCode = AuthorizationCodeValidator.createAuthorizer(servletContext)
                        .withClientId(clientId)
                        .validate(code);
            } catch (TokenAuthenticationException e) {
                throw new TokenRequestException(UNAUTHORIZED_CLIENT);
            }

            final String token;
            try {
                token = ReportProviderTokenGenerator.createGenerator(servletContext)
                        .withSubject(authorizationCode.getSubject())
                        .withClientId(clientId)
                        .withStudyInstanceUIDs(authorizationCode.getStudyInstanceUIDs())
                        .generate(REPORT_PROVIDER_TOKEN_LIFETIME);
            } catch (TokenAuthenticationException e) {
                throw new TokenRequestException(UNAUTHORIZED_CLIENT, e.getMessage(), e);
            }

            return Response.ok(TokenResponseEntity.createEntity(token, REPORT_PROVIDER_TOKEN_LIFETIME)).build();
        }
    },
    PASSWORD("password") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(UNSUPPORTED_GRANT_TYPE);
        }
    },
    CLIENT_CREDENTIALS("client_credentials") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(UNSUPPORTED_GRANT_TYPE);
        }
    },
    JWT_ASSERTION("urn:ietf:params:oauth:grant-type:jwt-bearer") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(UNSUPPORTED_GRANT_TYPE);
        }
    },
    SAML_ASSERTION("urn:ietf:params:oauth:grant-type:saml2-bearer") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            throw new TokenRequestException(UNSUPPORTED_GRANT_TYPE);
        }
    },
    EXCHANGE("urn:ietf:params:oauth:grant-type:token-exchange") {
        public Response processGrant(SecurityContext securityContext, ServletContext servletContext, MultivaluedMap<String, String> form) {
            verifySingle(form, "scope");
            verifySingle(form, "subject_token");
            verifySingle(form, "subject_token_type");
            verifySingle(form, "study_instance_uid");
            verifySingle(form, "series_instance_uid");

            final String scope = form.getFirst("scope");
            final String subjectToken = form.getFirst("subject_token");
            final String subjectTokenType = form.getFirst("subject_token_type");
            final String studyInstanceUID = form.getFirst("study_instance_uid");
            final String seriesInstanceUID = form.getFirst("series_instance_uid");

            if (!subjectTokenType.equals("urn:ietf:params:oauth:token-type:access_token")) {
                throw new TokenRequestException(INVALID_REQUEST);
            }

            if (scope.equals("pep")) {
                String pepToken = PepTokenGenerator.createGenerator(servletContext)
                        .withToken(subjectToken)
                        .withStudyInstanceUID(studyInstanceUID)
                        .withSeriesInstanceUID(seriesInstanceUID)
                        .generate();
                return Response.ok(TokenResponseEntity.createEntity(pepToken, 3600L)).build();
            } else if (scope.equals("viewer")) {
                return getViewerToken(grantType, assertionToken, studyInstanceUID, sourceType, sourceId, returnUser);
            } else {
                throw new TokenRequestException(INVALID_SCOPE);
            }
        }
    };

    final private static long REPORT_PROVIDER_TOKEN_LIFETIME = 60 * 60 * 5; // 5 hours

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

    private static void verifySingle(final MultivaluedMap<String, String> form, final String param) throws TokenRequestException {
        if (form.get(param).size() != 1) {
            throw new TokenRequestException(INVALID_REQUEST, "Must have a single " + param);
        }
    }
}
