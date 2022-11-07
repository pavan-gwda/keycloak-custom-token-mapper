package com.fortytwo;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import java.util.ArrayList;
import java.util.List;

/**
 * An OIDC protocol mapper that retrieves data from request header adds it as a claim to the token(s).
 */
@Slf4j
public class CustomOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "oidc-custom-42-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private static final String IDENTIFIER_HEADER_NAME = PROVIDER_ID + ".id_header";
    private static final String TOKEN_TYPE_HEADER_NAME = PROVIDER_ID + ".tt_header";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty identifierProperty = new ProviderConfigProperty();
        identifierProperty.setName(IDENTIFIER_HEADER_NAME);
        identifierProperty.setLabel("Identifier Header name");
        identifierProperty.setType(ProviderConfigProperty.STRING_TYPE);
        identifierProperty.setHelpText("Header name which will be passed");
        configProperties.add(identifierProperty);

        ProviderConfigProperty tokenTypeProperty = new ProviderConfigProperty();
        tokenTypeProperty.setName(TOKEN_TYPE_HEADER_NAME);
        tokenTypeProperty.setLabel("Token type Header name");
        tokenTypeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        tokenTypeProperty.setHelpText("Token type  which will be passed");
        configProperties.add(tokenTypeProperty);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomOIDCProtocolMapper.class);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Custom 42 mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Add custom header value to token.";
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {


        String idHeaderString = mappingModel.getConfig().get(IDENTIFIER_HEADER_NAME);
        String ttHeaderString = mappingModel.getConfig().get(TOKEN_TYPE_HEADER_NAME);
        log.debug("Header key : {}", idHeaderString);
        List<String> headerValueIdentifier = keycloakSession.getContext().getRequestHeaders().getRequestHeader(idHeaderString);
        List<String> headerValueTokenType = keycloakSession.getContext().getRequestHeaders().getRequestHeader(ttHeaderString);

        if (headerValueIdentifier != null && !headerValueIdentifier.isEmpty()) {
           OIDCAttributeMapperHelper.mapClaim(token, mappingModel, headerValueIdentifier.get(0));
        }
        if (headerValueTokenType != null && !headerValueTokenType.isEmpty()) {
            OIDCAttributeMapperHelper.mapClaim(token, mappingModel, headerValueTokenType.get(0));
        }

    }


}