package online.kheops.auth_server.report_provider;

import com.auth0.jwt.interfaces.DecodedJWT;
import online.kheops.auth_server.report_provider.metadata.OidcMetadata;

import java.util.Map;

public interface OidcProvider {

  OidcMetadata getOidcMetadata() throws OidcProviderException;

  DecodedJWT validateAccessToken(String accessToken) throws OidcProviderException;

  Map<String, String> getUserInfo(String token) throws OidcProviderException;
}
