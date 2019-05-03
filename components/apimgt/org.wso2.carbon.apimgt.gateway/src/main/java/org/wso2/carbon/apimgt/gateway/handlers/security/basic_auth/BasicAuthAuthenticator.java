/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.apimgt.gateway.handlers.security.basic_auth;

import io.swagger.models.Swagger;
import io.swagger.parser.SwaggerParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Base64;
import org.wso2.carbon.apimgt.gateway.MethodStats;
import org.wso2.carbon.apimgt.gateway.handlers.security.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;
import org.apache.synapse.config.Entry;

import java.util.Map;

/**
 * An API consumer authenticator which authenticates user requests using
 * Basic Authentication which uses username and password for authentication.
 */
public class BasicAuthAuthenticator implements Authenticator {

    private static final Log log = LogFactory.getLog(BasicAuthAuthenticator.class);
    private final String basicAuthKeyHeaderSegment = "Basic";
    private final String oauthKeyHeaderSegment = "Bearer";
    private final String authHeaderSplitter = ",";

    private String securityHeader;
    private String requestOrigin;
    private boolean removeOAuthHeadersFromOutMessage;
    private BasicAuthCredentialValidator basicAuthCredentialValidator;
    private String apiId;
    private Swagger swagger = null;


    /**
     * Initialize the authenticator with the required parameters.
     *
     * @param authorizationHeader the Authorization header
     * @param removeOAuthHeader whether the OAuth header need to be removed before passing to the backend or not
     * @param apiId the API Identifier
     */
    public BasicAuthAuthenticator(String authorizationHeader, boolean removeOAuthHeader, String apiId) {
        this.securityHeader = authorizationHeader;
        this.removeOAuthHeadersFromOutMessage = removeOAuthHeader;
        this.apiId = apiId;
    }

    /**
     * Set the BasicAuthCredentialValidator
     *
     * @param basicAuthCredentialValidator the BasicAuthCredentialValidator instance to be set
     */
    public void setBasicAuthCredentialValidator(BasicAuthCredentialValidator basicAuthCredentialValidator) {
        this.basicAuthCredentialValidator = basicAuthCredentialValidator;
    }

    /**
     * Initializes this authenticator instance.
     *
     * @param env Current SynapseEnvironment instance
     */
    public void init(SynapseEnvironment env) {
        try {
            this.basicAuthCredentialValidator = new BasicAuthCredentialValidator(env);
        } catch (APISecurityException e) {
            log.error(e);
        }
    }

    /**
     * Destroys this authenticator and releases any resources allocated to it.
     */
    @java.lang.Override
    public void destroy() {}

    /**
     * Authenticates the given request to see if an API consumer is allowed to access
     * a particular API or not.
     *
     * @param synCtx The message to be authenticated
     * @return true if the authentication is successful (never returns false)
     * @throws APISecurityException If an authentication failure or some other error occurs
     */
    @MethodStats
    public boolean authenticate(MessageContext synCtx) throws APISecurityException {
        if (log.isDebugEnabled()) {
            log.info("Basic Authentication initialized");
        }

        if (swagger == null && apiId != null) {
            Entry localEntryObj = (Entry) synCtx.getConfiguration().getLocalRegistry().get(apiId);
            if (localEntryObj != null) {
                SwaggerParser parser = new SwaggerParser();
                swagger = parser.parse(localEntryObj.getValue().toString());
            }
        }

        String[] credentials = extractBasicAuthCredentials(synCtx);
        String username = credentials[0];
        String password = credentials[1];

        boolean logged = basicAuthCredentialValidator.validate(username, password);
        if (!logged) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    "Authentication failed due to username & password mismatch");
        } else { // username password matches
            //scope validation
            boolean scopesValid = basicAuthCredentialValidator.validateScopes(username, swagger, synCtx);

            if (scopesValid) {
                //Create a dummy AuthenticationContext object with hard coded values for
                // Tier and KeyType. This is because we cannot determine the Tier nor Key
                // Type without subscription information..
                AuthenticationContext authContext = new AuthenticationContext();
                authContext.setAuthenticated(true);
                authContext.setTier(APIConstants.UNAUTHENTICATED_TIER);
                authContext.setStopOnQuotaReach(true);//Since we don't have details on unauthenticated tier we setting stop on quota reach true
                //Resource level throttling is not considered, hence assigning the unlimited tier for that
                VerbInfoDTO verbInfoDTO = new VerbInfoDTO();
                verbInfoDTO.setThrottling(APIConstants.UNLIMITED_TIER);
                synCtx.setProperty(APIConstants.VERB_INFO_DTO, verbInfoDTO);

                //In basic authentication scenario, we will use the username for throttling.
                authContext.setApiKey(username);
                authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
                authContext.setUsername(username);
                authContext.setCallerToken(null);
                authContext.setApplicationName(null);
                authContext.setApplicationId(username); //Set username as application ID in basic auth scenario
                authContext.setConsumerKey(null);
                APISecurityUtils.setAuthenticationContext(synCtx, authContext, null);

                return true;
            }
            throw new APISecurityException(APISecurityConstants.INVALID_SCOPE, "Scope validation failed");
        }
    }

    /**
     * Extract the basic authentication credentials from the authorization header of the message
     *
     * @param synCtx The message to be authenticated
     * @return an String array containing username and password
     * @throws APISecurityException in case of invalid authorization header or no header
     */
    protected String[] extractBasicAuthCredentials(MessageContext synCtx) throws APISecurityException {
        Map headers = (Map) ((Axis2MessageContext) synCtx).getAxis2MessageContext().
                getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null) {
            String authHeader = (String) headers.get(securityHeader);
            if (authHeader == null) {
                throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_CREDENTIALS,
                        "Basic Auth credentials not found");
            } else {
                if (authHeader.contains(basicAuthKeyHeaderSegment)) {
                    String[] tempAuthHeader = authHeader.split(authHeaderSplitter);
                    String remainingAuthHeader = "";
                    for (int i = 0; i < tempAuthHeader.length; i++) {
                        String h = tempAuthHeader[i];
                        if (h.trim().startsWith(basicAuthKeyHeaderSegment)) {
                            authHeader = h.trim();
                        } else if (h.trim().startsWith(oauthKeyHeaderSegment) && removeOAuthHeadersFromOutMessage) {
                            //If oauth header is configured to be removed at the gateway, remove it
                            continue;
                        } else {
                            remainingAuthHeader += h;
                            if (i < tempAuthHeader.length - 1) {
                                remainingAuthHeader += authHeaderSplitter;
                            }
                        }
                    }
                    //Remove authorization headers sent for authentication at the gateway and pass others to the backend
                    if (remainingAuthHeader != "") {
                        headers.put(securityHeader, remainingAuthHeader);
                    } else {
                        headers.remove(securityHeader);
                    }

                    try {
                        String authKey = new String(Base64.decode(authHeader.substring(6).trim())); // len(Basic) = 5
                        if (authKey.contains(":")) {
                            return authKey.split(":");
                        } else {
                            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                    "Invalid authorization key");
                        }
                    } catch (WSSecurityException e) {
                        throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                                "Invalid authorization key");
                    }
                } else {
                    throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_CREDENTIALS,
                            "Basic Auth credentials not found");
                }
            }
        }
        throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_CREDENTIALS,
                "Basic Auth credentials not found");
    }

    /**
     * Returns a string representation of the authentication challenge imposed by this
     * authenticator. In case of an authentication failure this value will be sent back
     * to the API consumer in the form of a WWW-Authenticate header.
     *
     * @return A string representation of the authentication challenge
     */
    public String getChallengeString() {
        return "Basic Auth realm=\"WSO2 API Manager\"";
    }


    /**
     * Returns the origin of the request
     *
     * @return returns the origin of the request
     */
    public String getRequestOrigin() {
        return requestOrigin;
    }

    /**
     * Sets the origin of the request
     *
     * @param requestOrigin the origin of the request
     */
    public void setRequestOrigin(String requestOrigin) {
        this.requestOrigin = requestOrigin;
    }

}
