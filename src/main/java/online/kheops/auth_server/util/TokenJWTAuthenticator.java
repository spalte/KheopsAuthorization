package online.kheops.auth_server.util;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import javax.servlet.ServletContext;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class TokenJWTAuthenticator {
    private static final String HOST_ROOT_PARAMETER = "online.kheops.client.dicomwebproxysecret";
    private static final String RS256 = "RS256";
    private static final Client CLIENT = ClientBuilder.newClient();

    final private ServletContext context;
    private String clientId;
    private String clientJWT;
    private DecodedJWT decodedJWT;


    public static TokenJWTAuthenticator newAuthenticator(final ServletContext context) {
        return new TokenJWTAuthenticator(context);
    }

    private TokenJWTAuthenticator(ServletContext context) {
        this.context = context;
    }

    public TokenJWTAuthenticator clientId(final String clientId) {
        this.clientId = Objects.requireNonNull(clientId);
        return this;
    }

    public TokenJWTAuthenticator clientJWT(final String clientJWT) throws TokenAuthenticationException {
        this.clientJWT = Objects.requireNonNull(clientJWT);

        try {
            decodedJWT = JWT.decode(clientJWT);
        } catch (JWTDecodeException e) {
            throw new TokenAuthenticationException("Unable to decode the JWT");
        }

        return this;
    }

    public TokenPrincipal authenticate() throws TokenAuthenticationException {
        Objects.requireNonNull(clientId);
        Objects.requireNonNull(clientJWT);
        basicValidation();

        RSAPublicKey publicKey = getPublicKey();
        final RSAKeyProvider keyProvider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String kid) {
                return publicKey;
            }

            // implemented to get rid of warnings
            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };

        final DecodedJWT jwt;
        try {
            jwt = JWT.require(Algorithm.RSA256(keyProvider))
                    .acceptLeeway(5)
                    .withIssuer(getConfigurationHost())
                    .withSubject(clientId)
                    .withAudience(getAudienceHost())
                    .build().verify(clientJWT);
        } catch (JWTVerificationException e) {
            throw new TokenAuthenticationException("Unable to verify the JWT", e);
        }

        return new TokenPrincipal() {
            @Override
            public TokenClientKind getClientKind() {
                return TokenClientKind.REPORT_PROVIDER;
            }

            @Override
            public String getName() {
                return clientId;
            }
        };
    }

    private void basicValidation() throws TokenAuthenticationException {
        if (!decodedJWT.getAlgorithm().equals(RS256)) {
            throw new TokenAuthenticationException("Unknown JWT signing algorithm: " + decodedJWT.getAlgorithm());
        }
    }

    private String getKeyId() throws TokenAuthenticationException
    {
        Objects.requireNonNull(decodedJWT);
        return decodedJWT.getKeyId();
    }

    private RSAPublicKey getPublicKey() throws TokenAuthenticationException {
        JwkProvider provider = new UrlJwkProvider(getJWKSUri().toString());
        try {
            return (RSAPublicKey) provider.get(getKeyId()).getPublicKey(); //throws Exception when not found or can't get one
        } catch (JwkException e) {
            throw new TokenAuthenticationException("Bad configuration URI", e);
        }
    }

    private String getConfigurationHost() throws TokenAuthenticationException {
        URI configurationURI = getConfigurationURI();

        return configurationURI.getScheme() + "://" +  configurationURI.getAuthority();
    }

    private String getAudienceHost() throws TokenAuthenticationException {
        // TODO
        return null;
    }

    private URI getConfigurationURI() throws TokenAuthenticationException {
        try {
            return new URI("");
        } catch (URISyntaxException e) {
            throw new TokenAuthenticationException("Bad configuration URI", e);
        }
    }

    private URI getJWKSUri() throws TokenAuthenticationException {
        // TODO
        return null;
    }

}
