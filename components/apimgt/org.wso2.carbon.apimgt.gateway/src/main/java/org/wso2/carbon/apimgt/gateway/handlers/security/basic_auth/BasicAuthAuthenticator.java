/*
 *  Copyright WSO2 Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.apimgt.gateway.handlers.security.basic_auth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.gateway.MethodStats;
import org.wso2.carbon.apimgt.gateway.handlers.security.*;
import org.wso2.carbon.apimgt.gateway.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;

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

    private String securityHeader = HttpHeaders.AUTHORIZATION;
    private String requestOrigin;
    private boolean removeOAuthHeadersFromOutMessage = true;
    private JSONObject resourceScopes;
    private BasicAuthCredentialValidator basicAuthCredentialValidator;

    public void setBasicAuthCredentialValidator(BasicAuthCredentialValidator basicAuthCredentialValidator) {
        this.basicAuthCredentialValidator = basicAuthCredentialValidator;
    }

    public BasicAuthAuthenticator() {
    }

    public BasicAuthAuthenticator(String authorizationHeader, boolean removeOAuthHeader, String resourceScopes) {
        this.securityHeader = authorizationHeader;
        this.removeOAuthHeadersFromOutMessage = removeOAuthHeader;

        if (resourceScopes != null) {
            try {
                String resourceScopeString = new String(Base64.decode(resourceScopes));
                JSONParser parser = new JSONParser();
                try {
                    this.resourceScopes = (JSONObject) parser.parse(resourceScopeString);
                } catch (ParseException e) {
                    log.error(e);
                }
            } catch (WSSecurityException e) {
                log.error(e);
            }
        }
    }

    public void init(SynapseEnvironment env) {
        try {
            this.basicAuthCredentialValidator = new BasicAuthCredentialValidator(env);
        } catch (APISecurityException e) {
            log.error(e);
        }
    }

    @java.lang.Override
    public void destroy() {

    }

    @MethodStats
    public boolean authenticate(MessageContext synCtx) throws APISecurityException {
        log.info("Basic Authentication initialized");
        String username = null;
        String password = null;

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
                            String credentials[] = authKey.split(":");
                            username = credentials[0];
                            password = credentials[1];
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

        boolean logged = basicAuthCredentialValidator.validate(username, password);
        if (!logged) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                    "Authentication failed due to username & password mismatch");
        } else { // username password matches
            //scope validation
            boolean scopesValid = basicAuthCredentialValidator.validateScopes(username, resourceScopes, synCtx);

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
        }
        return false;
    }

    public String getChallengeString() {
        return "Basic Auth realm=\"WSO2 API Manager\"";
    }

    public String getRequestOrigin() {
        return requestOrigin;
    }

    public void setRequestOrigin(String requestOrigin) {
        this.requestOrigin = requestOrigin;
    }

}
