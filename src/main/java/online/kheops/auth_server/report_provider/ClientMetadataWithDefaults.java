package online.kheops.auth_server.report_provider;

import online.kheops.auth_server.token.TokenClientAuthenticationType;

import java.util.*;

import static online.kheops.auth_server.report_provider.ClientMetadataListGrantTypeParameter.GRANT_TYPES;
import static online.kheops.auth_server.report_provider.ClientMetadataListResponseTypeParameter.RESPONSE_TYPES;
import static online.kheops.auth_server.report_provider.ClientMetadataOptionalAlgorithmParameter.*;
import static online.kheops.auth_server.report_provider.ClientMetadataOptionalApplicationTypeParameter.APPLICATION_TYPE;
import static online.kheops.auth_server.report_provider.ClientMetadataOptionalAuthMethodParameter.TOKEN_ENDPOINT_AUTH_METHOD;
import static online.kheops.auth_server.report_provider.ClientMetadataOptionalBooleanParameter.REQUIRE_AUTH_TIME;
import static online.kheops.auth_server.report_provider.ClientMetadataOptionalEncodingParameter.*;
import static online.kheops.auth_server.report_provider.EmptyClientMetadata.EMPTY_CLIENT_METADATA;

public final class ClientMetadataWithDefaults implements ClientMetadata {

    public static final ClientMetadataWithDefaults EMPTY_DEFAULT_METADATA = new ClientMetadataWithDefaults(EMPTY_CLIENT_METADATA);

    private final ClientMetadata clientMetadata;

    ClientMetadataWithDefaults(ClientMetadata clientMetadata) {
        this.clientMetadata = clientMetadata;
    }

    public static ClientMetadata from(ClientMetadata clientMetadata) {
        return new ClientMetadataWithDefaults(clientMetadata);
    }

    private static final ClientMetadataParameterMap DEFAULT_VALUES = defaultValues();

    @Override
    public <T> T getValue(ClientMetadataParameter<T> parameter) {
        T value = clientMetadata.getValue(parameter);
        if (DEFAULT_VALUES.containsKey(parameter)) {
            if ((value instanceof Optional && ((Optional<?>) value).isEmpty())
                    || (value instanceof List && ((List<?>) value).isEmpty())) {
                return DEFAULT_VALUES.get(parameter);
            }
        }
        return value;
    }

    @Override
    public <T> T getValue(ClientMetadataParameter<T> parameter, Locale local) {
        // none of the localizable parameters have defaults
        return clientMetadata.getValue(parameter, local);
    }

    private static ClientMetadataParameterMap defaultValues() {
        final ClientMetadataParameterMap defaultValues = new ClientMetadataParameterMap();

        defaultValues.put(RESPONSE_TYPES, Collections.singletonList(ResponseType.CODE));
        defaultValues.put(GRANT_TYPES, Collections.singletonList(GrantType.AUTHORIZATION_CODE));
        defaultValues.put(APPLICATION_TYPE, Optional.of(ApplicationType.WEB));
        defaultValues.put(ID_TOKEN_SIGNED_RESPONSE_ALG, Optional.of(Algorithm.RS256));
        defaultValues.put(ID_TOKEN_ENCRYPTED_RESPONSE_ALG, Optional.of(Algorithm.NONE));
        defaultValues.put(ID_TOKEN_ENCRYPTED_RESPONSE_ENC, Optional.of(Encoding.A128CBC_HS256));
        defaultValues.put(USERINFO_SIGNED_RESPONSE_ALG, Optional.of(Algorithm.NONE));
        defaultValues.put(USERINFO_ENCRYPTED_RESPONSE_ALG, Optional.of(Algorithm.NONE));
        defaultValues.put(USERINFO_ENCRYPTED_RESPONSE_ENC, Optional.of(Encoding.A128CBC_HS256));
        defaultValues.put(REQUEST_OBJECT_SIGNING_ALG, Optional.of(Algorithm.ANY_SUPPORTED));
        defaultValues.put(REQUEST_OBJECT_ENCRYPTION_ALG, Optional.of(Algorithm.UNDECLARED));
        defaultValues.put(REQUEST_OBJECT_ENCRYPTION_ENC, Optional.of(Encoding.A128CBC_HS256));
        defaultValues.put(TOKEN_ENDPOINT_AUTH_METHOD, Optional.of(TokenClientAuthenticationType.CLIENT_SECRET_BASIC));
        defaultValues.put(TOKEN_ENDPOINT_AUTH_SIGNING_ALG, Optional.of(Algorithm.RS256));
        defaultValues.put(REQUIRE_AUTH_TIME, Optional.of(false));

        return defaultValues;
    }
}