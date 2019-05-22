package online.kheops.auth_server.resource;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import online.kheops.auth_server.annotation.FormURLEncodedContentType;
import online.kheops.auth_server.annotation.TokenSecurity;
import online.kheops.auth_server.assertion.*;
import online.kheops.auth_server.capability.ScopeType;
import online.kheops.auth_server.entity.Capability;
import online.kheops.auth_server.entity.ReportProvider;
import online.kheops.auth_server.entity.User;
import online.kheops.auth_server.principal.KheopsPrincipalInterface;
import online.kheops.auth_server.report_provider.ClientIdNotFoundException;
import online.kheops.auth_server.series.SeriesNotFoundException;
import online.kheops.auth_server.user.UserNotFoundException;
import online.kheops.auth_server.util.*;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

import javax.servlet.ServletContext;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.xml.bind.annotation.XmlElement;
import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import static javax.ws.rs.core.Response.Status.*;
import static online.kheops.auth_server.report_provider.ReportProviders.getReportProvider;
import static online.kheops.auth_server.user.Users.getOrCreateUser;
import static online.kheops.auth_server.util.Consts.ALBUM;
import static online.kheops.auth_server.util.Consts.INBOX;
import static online.kheops.auth_server.util.Tools.checkValidUID;
import static online.kheops.auth_server.util.TokenRequestException.Error.UNSUPPORTED_GRANT_TYPE;
import static online.kheops.auth_server.util.TokenRequestException.Error.INVALID_REQUEST;


@Path("/")
public class TokenResource
{
    private static final Logger LOG = Logger.getLogger(TokenResource.class.getName());

    @Context
    ServletContext context;

    @Context
    SecurityContext securityContext;

    static class TokenResponse {
        @XmlElement(name = "access_token")
        String accessToken;
        @XmlElement(name = "token_type")
        String tokenType;
        @XmlElement(name = "expires_in")
        Long expiresIn;
        @XmlElement(name = "user")
        String user;
    }

    static class IntrospectResponse {
        @XmlElement(name = "active")
        boolean active;
        @XmlElement(name = "scope")
        String scope;
    }



    @POST
    @TokenSecurity
    @FormURLEncodedContentType
    @Path("/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(final MultivaluedMap<String, String> form) {

        if (form.get("grant_type").size() != 0) {
            throw new TokenRequestException(INVALID_REQUEST, "Missing or duplicate grant_type");
        }

        final TokenGrantType grantType;
        try {
            grantType = TokenGrantType.fromString(form.getFirst("grant_type"));
        } catch (IllegalArgumentException e) {
            throw new TokenRequestException(UNSUPPORTED_GRANT_TYPE, "Missing or duplicate grant_type");
        }

        return grantType.processGrant(securityContext, context, form);
    }

    private Response getClientToken(String grantType, String clientId, String clientAssertionType, String clientAssertion) {

        //verify dicom SR JWT signature

        final ReportProvider reportProvider;
        try {
            reportProvider = getReportProvider(clientId);
        } catch (ClientIdNotFoundException e) {
            errorResponse.error = "invalid_client_id";
            errorResponse.errorDescription = "client id not found";
            return Response.status(BAD_REQUEST).entity(new TokenErrorResponse(UNSUPPORTED_GRANT_TYPE).build();
        }

        reportProvider.getUrl();

        final Assertion assertion;
        try {
            assertion = AssertionVerifier.createAssertion(clientAssertion, grantType);
        } catch (UnknownGrantTypeException e) {
            errorResponse.errorDescription = e.getMessage();
            LOG.log(Level.WARNING, "Unknown grant type", e);
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        } catch (BadAssertionException e) {
            errorResponse.errorDescription = e.getMessage();
            LOG.log(Level.WARNING, "Error validating a token", e);
            return Response.status(UNAUTHORIZED).entity(errorResponse).build();
        } catch (DownloadKeyException e) {
            LOG.log(Level.SEVERE, "Error downloading the public key", e);
            errorResponse.error = "server_error";
            errorResponse.errorDescription = "error";
            return Response.status(BAD_GATEWAY).entity(errorResponse).build();
        }

        return null;
    }

    private Response getViewerToken(String grantType, String assertionToken,
                                 String studyInstanceUID,
                                 String sourceType, String sourceId, boolean returnUser) {

        final ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.error = "invalid_parameters";

        if (studyInstanceUID == null || sourceType == null) {
            errorResponse.errorDescription = "With the scope: 'viewer', 'study_instance_uid' and 'source_type' must be set";
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        }
        if (!checkValidUID(studyInstanceUID)) {
            errorResponse.errorDescription = "'study_instance_uid' is not a valid UID";
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        }
        if (!sourceType.equals(ALBUM) && !sourceType.equals(INBOX)) {
            errorResponse.errorDescription = "'source_type' can be only '" + ALBUM + "' or '" + INBOX + "'";
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        }
        if (sourceType.equals(ALBUM) && (sourceId.isEmpty() || sourceId == null)) {
            errorResponse.errorDescription = "'source_id' must be set when 'source_type'=" + ALBUM;
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        }


        final String token;
        final long expiresIn;
        errorResponse.error = "assertion";

        final Assertion assertion;
        try {
            assertion = AssertionVerifier.createAssertion(assertionToken, grantType);
        } catch (UnknownGrantTypeException e) {
            errorResponse.errorDescription = e.getMessage();
            LOG.log(Level.WARNING, "Unknown grant type", e);
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        } catch (BadAssertionException e) {
            errorResponse.errorDescription = e.getMessage();
            LOG.log(Level.WARNING, "Error validating a token", e);
            return Response.status(UNAUTHORIZED).entity(errorResponse).build();
        } catch (DownloadKeyException e) {
            LOG.log(Level.SEVERE, "Error downloading the public key", e);
            errorResponse.error = "server_error";
            errorResponse.errorDescription = "error";
            return Response.status(BAD_GATEWAY).entity(errorResponse).build();
        }

        try {
            getOrCreateUser(assertion.getSub());
        } catch (UserNotFoundException e) {
            LOG.log(Level.WARNING, "User not found", e);
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }


        // Generate a new Viewer token (JWE)

        if (assertion.getTokenType() == Assertion.TokenType.VIEWER_TOKEN ||
                assertion.getTokenType() == Assertion.TokenType.PEP_TOKEN ) {
            errorResponse.error = "unauthorized";
            errorResponse.errorDescription = "Request a viewer token is unauthorized with a pep token or a viewer token";
            return Response.status(UNAUTHORIZED).entity(errorResponse).build();
        }

        try {
            final JsonWebEncryption jwe = new JsonWebEncryption();

            final JSONObject data = new JSONObject();
            data.put(Consts.JWE.TOKEN, assertionToken);
            data.put(Consts.JWE.SOURCE_ID, sourceId);
            data.put(Consts.JWE.IS_INBOX, sourceType.equals(INBOX));
            data.put(Consts.JWE.STUDY_INSTANCE_UID, studyInstanceUID);
            data.put(Consts.JWE.EXP, Date.from(Instant.now().plus(12, ChronoUnit.HOURS)));

            jwe.setPayload(data.toJSONString());
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            jwe.setKey(JweAesKey.getInstance().getKey());
            token = jwe.getCompactSerialization();
            expiresIn = 43200L;
        } catch (JoseException e) {
            LOG.log(Level.SEVERE, "JoseException", e);
            return Response.status(INTERNAL_SERVER_ERROR).entity(e.getStackTrace()).build();//TODO
        }

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.accessToken = token;
        tokenResponse.tokenType = "Bearer";
        tokenResponse.expiresIn = expiresIn;
        if (returnUser) {
            tokenResponse.user = assertion.getSub();
        }

        LOG.info(() ->"Returning viewer token for user: " + assertion.getSub() + "for studyInstanceUID " + studyInstanceUID);

        return Response.status(OK).entity(tokenResponse).build();
    }

    @POST
    @FormURLEncodedContentType
    @Path("/token/introspect")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response introspect(@FormParam("grant_type") String grantType,
                               @FormParam("assertion") String assertionToken) {

        final ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.error = "invalid_grant";
        final IntrospectResponse intreospectResponse = new IntrospectResponse();

        final Assertion assertion;
        try {
            assertion = AssertionVerifier.createAssertion(assertionToken, grantType);
        } catch (UnknownGrantTypeException e) {
            errorResponse.errorDescription = e.getMessage();
            LOG.log(Level.WARNING, "Unknown grant type", e);
            return Response.status(BAD_REQUEST).entity(errorResponse).build();
        } catch (BadAssertionException e) {
            errorResponse.errorDescription = e.getMessage();
            LOG.log(Level.WARNING, "Error validating a token", e);
            intreospectResponse.error = errorResponse;
            intreospectResponse.active = false;
            return Response.status(OK).entity(intreospectResponse).build();
        } catch (DownloadKeyException e) {
            LOG.log(Level.SEVERE, "Error downloading the public key", e);
            errorResponse.error = "server_error";
            errorResponse.errorDescription = "error";
            return Response.status(BAD_GATEWAY).entity(errorResponse).build();
        }


        final User callingUser;
        try {
            callingUser = getOrCreateUser(assertion.getSub());
        } catch (UserNotFoundException e) {
            LOG.log(Level.WARNING, "user not found", e);
            errorResponse.error = "unknown_user";
            errorResponse.errorDescription = "The user was not found in the DB";
            intreospectResponse.error = errorResponse;
            intreospectResponse.active = false;
            return Response.status(OK).entity(intreospectResponse).build();
        }

        final Capability capability = assertion.getCapability().orElse(null);

        if(capability != null) {
            if (capability.getScopeType().equalsIgnoreCase(ScopeType.ALBUM.name())) {
                intreospectResponse.scope = (capability.isWritePermission()?"write ":"") +
                        (capability.isReadPermission()?"read ":"") +
                        (capability.isDownloadPermission()?"download ":"") +
                        (capability.isAppropriatePermission()?"appropriate ":"");
                if (intreospectResponse.scope.length() > 0) {
                    intreospectResponse.scope = intreospectResponse.scope.substring(0, intreospectResponse.scope.length() - 1);
                }
            } else {
                intreospectResponse.scope = "read write";
            }
        } else if(assertion.getViewer().isPresent()) {
            intreospectResponse.scope = "read";
        } else {
            intreospectResponse.scope = "read write";
        }

        intreospectResponse.active = true;
        return Response.status(OK).entity(intreospectResponse).build();
    }
}

