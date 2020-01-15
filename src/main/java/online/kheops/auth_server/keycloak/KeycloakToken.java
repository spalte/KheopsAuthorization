package online.kheops.auth_server.keycloak;

import online.kheops.auth_server.util.ErrorResponse;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.UriBuilder;
import javax.xml.bind.annotation.XmlElement;
import java.net.URI;
import java.time.Instant;
import java.util.logging.Logger;

import static javax.ws.rs.core.HttpHeaders.CONTENT_TYPE;
import static javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED;

public class KeycloakToken {
    private static final Logger LOG = Logger.getLogger(KeycloakToken.class.getName());

    private static final long MINIMUM_VALIDITY = 60;  //secondes
    private static final Client CLIENT = ClientBuilder.newClient();

    private static URI tokenUri;
    private static KeycloakToken instance = null;
    private static Form form;

    private String accessToken;
    private Instant renewTime;

    private static class TokenResponse {
        @XmlElement(name = "access_token")
        String accessToken;
        @XmlElement(name = "expires_in")
        long expiresIn;
    }

    private static class ConfigurationResponse {
        @XmlElement(name = "token_endpoint")
        String tokenEndpoint;
    }

    private KeycloakToken() throws KeycloakException{
        if (tokenUri == null) {
            tokenUri = getTokenUri();
        }

        form = new Form();
        form.param("grant_type", "client_credentials");
        form.param("client_id", KeycloakContextListener.getKeycloakClientId());
        form.param("client_secret", KeycloakContextListener.getKeycloakClientSecret());
    }

    public static synchronized KeycloakToken getInstance() throws KeycloakException{
        if (instance == null) {
            instance = new KeycloakToken();
        }
        return instance;
    }

    public String getToken() throws KeycloakException {
        if (renewTime == null || renewTime.isBefore(Instant.now())) {
            final TokenResponse tokenResponse;
            try {
                Invocation.Builder builder = CLIENT.target(tokenUri).request().header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED);
                tokenResponse = builder.post(Entity.form(form), TokenResponse.class);
                accessToken = tokenResponse.accessToken;
                renewTime = Instant.now().plusSeconds(tokenResponse.expiresIn - MINIMUM_VALIDITY);
            } catch (ProcessingException | WebApplicationException e) {
                final ErrorResponse errorResponse = new ErrorResponse.ErrorResponseBuilder()
                        .message("Error with authority provider")
                        .detail("Error getting an access token from: " + tokenUri)
                        .build();
                throw new KeycloakException(errorResponse, e);
            }
        }

        return accessToken;
    }

    public void removeToken() {
        accessToken = null;
        renewTime = null;
    }

    private URI getTokenUri() throws KeycloakException {
        final ConfigurationResponse response;
        try {
            response = CLIENT.target(KeycloakContextListener.getKeycloakOIDCConfigurationURI()).request().get(ConfigurationResponse.class);
            return UriBuilder.fromUri(response.tokenEndpoint).build();
        } catch (ProcessingException | WebApplicationException e) {
            final ErrorResponse errorResponse = new ErrorResponse.ErrorResponseBuilder()
                    .message("Error with authority provider")
                    .detail("Error during request OpenID Connect well-known from: " + KeycloakContextListener.getKeycloakOIDCConfigurationURI())
                    .build();
            throw new KeycloakException(errorResponse, e);
        }
    }

}
