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

import java.util.Map;

/**
 * An API consumer authenticator which authenticates user requests using
 * the OAuth protocol. This implementation uses some default token/delimiter
 * values to parse OAuth headers, but if needed these settings can be overridden
 * through the APIManagerConfiguration.
 */
public class BasicAuthAuthenticator implements Authenticator {

    private static final Log log = LogFactory.getLog(BasicAuthAuthenticator.class);

    private String securityHeader = HttpHeaders.AUTHORIZATION;
    private String basicAuthKeyHeaderSegment = "Basic";
    private String authHeaderSplitter = ",";
    private String securityContextHeader;
    private boolean removeOAuthHeadersFromOutMessage = true;
    private String requestOrigin;
    private JSONObject resourceScopes;
    private BasicAuthCredentialValidator basicAuthCredentialValidator;

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
        try {
            this.basicAuthCredentialValidator = new BasicAuthCredentialValidator();
        } catch (APISecurityException e) {
            log.error(e);
        }
    }

    public void init(SynapseEnvironment env) {
        initOAuthParams();
    }

    @java.lang.Override
    public void destroy() {

    }

    @MethodStats
    public boolean authenticate(MessageContext synCtx) throws APISecurityException {
        log.info("Basic Authentication initialized");
        String username = null;
        String password = null;

        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) synCtx).getAxis2MessageContext();
        Object headers = axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null && headers instanceof Map) {
            Map headersMap = (Map) headers;
            String authHeader = (String) headersMap.get(securityHeader);
            if (authHeader == null) {
                headersMap.clear();
                throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_CREDENTIALS,
                        "Basic Auth Header not found");
            } else {
                if (authHeader.contains(basicAuthKeyHeaderSegment)) {
                    try {
                        String[] tempAuthHeader = authHeader.split(authHeaderSplitter);
                        String remainingHeader = "";
                        for (String h : tempAuthHeader) {
                            if (h.trim().startsWith(basicAuthKeyHeaderSegment)) {
                                authHeader = h.trim();
                            } else {
                                remainingHeader += h + authHeaderSplitter;
                            }
                        }
                        if (removeOAuthHeadersFromOutMessage) {
                            if (tempAuthHeader.length > 1) {
                                headersMap.put(securityHeader, remainingHeader);
                            } else {
                                headersMap.remove(securityHeader);
                            }
                        }
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
                    throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_CREDENTIALS,
                            "Basic Auth Header not found");
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
                //Requests are throttled by the ApiKey that is set here. In an unauthenticated scenario,
                //we will use the username for throttling.
                //Username is extracted from the request
                authContext.setApiKey(username);
                authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
                authContext.setUsername(username);
                authContext.setCallerToken(null);
                authContext.setApplicationName(null);
                authContext.setApplicationId(username); //Set username as application ID in basic auth scenario
                authContext.setConsumerKey(null);
                APISecurityUtils.setAuthenticationContext(synCtx, authContext, securityContextHeader);

                return true;
            }
        }
        return false;
    }
    protected void initOAuthParams() {
        APIManagerConfiguration config = getApiManagerConfiguration();
        String value = config.getFirstProperty(APIConstants.REMOVE_OAUTH_HEADERS_FROM_MESSAGE);
        if (value != null) {
            removeOAuthHeadersFromOutMessage = Boolean.parseBoolean(value);
        }
        value = config.getFirstProperty(APIConstants.JWT_HEADER);
        if (value != null) {
            setSecurityContextHeader(value);
        }
    }

    protected APIManagerConfiguration getApiManagerConfiguration() {
        return ServiceReferenceHolder.getInstance().getAPIManagerConfiguration();
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

    public String getSecurityContextHeader() {
        return securityContextHeader;
    }

    public void setSecurityContextHeader(String securityContextHeader) {
        this.securityContextHeader = securityContextHeader;
    }

}
