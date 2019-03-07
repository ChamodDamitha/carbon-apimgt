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

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.RESTConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.mozilla.javascript.NativeObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.MethodStats;
import org.wso2.carbon.apimgt.gateway.handlers.security.*;
import org.wso2.carbon.apimgt.gateway.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.hostobjects.internal.HostObjectComponent;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.tracing.TracingSpan;
import org.wso2.carbon.apimgt.tracing.TracingTracer;
import org.wso2.carbon.apimgt.tracing.Util;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.PermissionUpdateUtil;
import org.wso2.carbon.metrics.manager.Level;
import org.wso2.carbon.metrics.manager.MetricManager;
import org.wso2.carbon.metrics.manager.Timer;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceUserStoreExceptionException;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URL;
import java.util.Map;
import java.util.TreeMap;

/**
 * An API consumer authenticator which authenticates user requests using
 * the OAuth protocol. This implementation uses some default token/delimiter
 * values to parse OAuth headers, but if needed these settings can be overridden
 * through the APIManagerConfiguration.
 */
public class BasicAuthAuthenticator implements Authenticator {

    private static final Log log = LogFactory.getLog(BasicAuthAuthenticator.class);

    private String securityHeader = HttpHeaders.AUTHORIZATION;
    private String defaultAPIHeader = "WSO2_AM_API_DEFAULT_VERSION";
    private String basicAuthKeyHeaderSegment = "Basic";
    private String authHeaderSplitter = ",";
    private String securityContextHeader;
    private boolean removeOAuthHeadersFromOutMessage = true;
    private boolean removeDefaultAPIHeaderFromOutMessage = true;
    private String clientDomainHeader = "referer";
    private String requestOrigin;
    private JSONObject resourceScopes;


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
                sendUnauthorizedResponse(axis2MessageContext, synCtx, "401");
                return false;
            } else {
                if (authHeader.contains(basicAuthKeyHeaderSegment)) {
                    try {
                        String[] tempAuthHeader = authHeader.split(authHeaderSplitter);
                        String remainingHeader = "";
                        for (String h: tempAuthHeader) {
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
                    sendUnauthorizedResponse(axis2MessageContext, synCtx, "401");
                    return false;
                }
            }
        }

        ConfigurationContext configurationContext = ServiceReferenceHolder.getInstance().getAxis2ConfigurationContext();
        APIManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(APIConstants.AUTH_MANAGER_URL);
        if (url == null) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, "API key manager URL unspecified");
        }

//        try {
//            AuthenticationAdminStub authAdminStub = new AuthenticationAdminStub(configurationContext, url +
//                    serviceName);
//            ServiceClient client = authAdminStub._getServiceClient();
//            Options options = client.getOptions();
//            options.setManageSession(true);
        RemoteUserStoreManagerServiceStub remoteUserStoreManagerServiceStub;
        try {
            remoteUserStoreManagerServiceStub = new RemoteUserStoreManagerServiceStub(configurationContext, url +
                    "RemoteUserStoreManagerService");
        } catch (AxisFault axisFault) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, axisFault.getMessage());
        }
        ServiceClient svcClient = remoteUserStoreManagerServiceStub._getServiceClient();
            CarbonUtils.setBasicAccessSecurityHeaders(config.getFirstProperty(APIConstants.AUTH_MANAGER_USERNAME),
                    config.getFirstProperty(APIConstants.AUTH_MANAGER_PASSWORD), svcClient);


//            String tenantDomain = MultitenantUtils.getTenantDomain(username);
//            //update permission cache before validate user
//            int tenantId = ServiceReferenceHolder.getInstance().getRealmService().getTenantManager()
//                    .getTenantId(tenantDomain);
//            if (tenantId == MultitenantConstants.INVALID_TENANT_ID) {
//                handleException("Invalid tenant domain.");
//            }
//            PermissionUpdateUtil.updatePermissionTree(tenantId);

        boolean logged;
        try {
            logged = remoteUserStoreManagerServiceStub.authenticate(username, password);
        } catch (Exception e) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, e.getMessage());
        }
        if (!logged) {
                throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                        "Authentication failed due to username & password mismatch");
            } else { // username password matches
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

//              Scope validation with user roles
                if (resourceScopes != null) {
                    String apiElectedResource = (String) synCtx.getProperty(APIConstants.API_ELECTED_RESOURCE);
                    String httpMethod = (String) axis2MessageContext.getProperty(APIConstants.DigestAuthConstants.HTTP_METHOD);
                    String resourceKey = apiElectedResource + ":" + httpMethod;
                    if (resourceScopes.containsKey(resourceKey)) {
                        String[] user_roles;
                        try {
                            user_roles = remoteUserStoreManagerServiceStub.getRoleListOfUser(username);
                        } catch (Exception e) {
                            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, e.getMessage());
                        }
                        JSONObject scope = (JSONObject) resourceScopes.get(resourceKey);
                        String allowed_roles = (String) scope.get("roles");
                        for (String role : user_roles) {
                            if (allowed_roles.contains(role)) {
                                return true;
                            }
                        }
                    } else {
//                      No scopes for the requested resource
                        return true;
                    }
                } else {
//                  No scopes for API
                    return true;
                }
                throw new APISecurityException(APISecurityConstants.INVALID_SCOPE, "Scope validation failed");
            }
//        } catch (Exception e) {
//            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, e.getMessage());
//        }
    }

    /**
     * Send unauthorized response
     *
     * @param axis2MessageContext
     * @param messageContext
     * @param status
     */
    private void sendUnauthorizedResponse(org.apache.axis2.context.MessageContext axis2MessageContext,
                                          MessageContext messageContext, String status) {
        axis2MessageContext.setProperty("HTTP_SC", status);
        axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
        messageContext.setProperty("RESPONSE", "true");
        messageContext.setTo(null);
        Axis2Sender.sendBack(messageContext);
    }

    private String removeLeadingAndTrailing(String base) {
        String result = base;

        if (base.startsWith("\"") || base.endsWith("\"")) {
            result = base.replace("\"", "");
        }
        return result.trim();
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
        return "OAuth2 realm=\"WSO2 API Manager\"";
    }

    private String getClientDomain(MessageContext synCtx) {
        String clientDomainHeaderValue = null;
        Map headers = (Map) ((Axis2MessageContext) synCtx).getAxis2MessageContext().
                getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null) {
            clientDomainHeaderValue = (String) headers.get(clientDomainHeader);
        }
        return clientDomainHeaderValue;
    }

    public String getRequestOrigin() {
        return requestOrigin;
    }

    public String getSecurityHeader() {
        return securityHeader;
    }

    public void setSecurityHeader(String securityHeader) {
        this.securityHeader = securityHeader;
    }

    public String getDefaultAPIHeader() {
        return defaultAPIHeader;
    }

    public void setDefaultAPIHeader(String defaultAPIHeader) {
        this.defaultAPIHeader = defaultAPIHeader;
    }


    public String getSecurityContextHeader() {
        return securityContextHeader;
    }

    public void setSecurityContextHeader(String securityContextHeader) {
        this.securityContextHeader = securityContextHeader;
    }

    public boolean isRemoveOAuthHeadersFromOutMessage() {
        return removeOAuthHeadersFromOutMessage;
    }

    public void setRemoveOAuthHeadersFromOutMessage(boolean removeOAuthHeadersFromOutMessage) {
        this.removeOAuthHeadersFromOutMessage = removeOAuthHeadersFromOutMessage;
    }

    public String getClientDomainHeader() {
        return clientDomainHeader;
    }

    public void setClientDomainHeader(String clientDomainHeader) {
        this.clientDomainHeader = clientDomainHeader;
    }

    public boolean isRemoveDefaultAPIHeaderFromOutMessage() {
        return removeDefaultAPIHeaderFromOutMessage;
    }

    public void setRemoveDefaultAPIHeaderFromOutMessage(boolean removeDefaultAPIHeaderFromOutMessage) {
        this.removeDefaultAPIHeaderFromOutMessage = removeDefaultAPIHeaderFromOutMessage;
    }

    public void setRequestOrigin(String requestOrigin) {
        this.requestOrigin = requestOrigin;
    }


}
