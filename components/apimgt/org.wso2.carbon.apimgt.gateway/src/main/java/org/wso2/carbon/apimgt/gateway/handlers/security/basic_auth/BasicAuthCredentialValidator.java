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
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.json.simple.JSONObject;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.hostobjects.internal.HostObjectComponent;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;
import org.wso2.carbon.utils.CarbonUtils;

import javax.cache.Cache;
import javax.cache.Caching;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BasicAuthCredentialValidator {

    private boolean gatewayKeyCacheEnabled;
    private static boolean gatewayUsernameCacheInit = false;
    private static boolean gatewayInvalidUsernameCacheInit = false;
    private static boolean gatewayResourceCacheInit = false;

    protected Log log = LogFactory.getLog(getClass());
    private RemoteUserStoreManagerServiceStub remoteUserStoreManagerServiceStub;

    public BasicAuthCredentialValidator() {

    }

    public BasicAuthCredentialValidator(SynapseEnvironment env) throws APISecurityException {
        this.gatewayKeyCacheEnabled = isGatewayTokenCacheEnabled();
        this.getGatewayUsernameCache();


        ConfigurationContext configurationContext = ServiceReferenceHolder.getInstance().getAxis2ConfigurationContext();
        APIManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(APIConstants.AUTH_MANAGER_URL);
        if (url == null) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, "API key manager URL unspecified");
        }

        try {
            remoteUserStoreManagerServiceStub = new RemoteUserStoreManagerServiceStub(configurationContext, url +
                    "RemoteUserStoreManagerService");
        } catch (AxisFault axisFault) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, axisFault.getMessage());
        }
        ServiceClient svcClient = remoteUserStoreManagerServiceStub._getServiceClient();
        CarbonUtils.setBasicAccessSecurityHeaders(config.getFirstProperty(APIConstants.AUTH_MANAGER_USERNAME),
                config.getFirstProperty(APIConstants.AUTH_MANAGER_PASSWORD), svcClient);
    }

    public boolean validate(String username, String password) throws APISecurityException {
        String providedPasswordHash = hashString(password);
        if (gatewayKeyCacheEnabled) {
            String cachedPasswordHash = (String) getGatewayUsernameCache().get(username);
            if (cachedPasswordHash != null && cachedPasswordHash.equals(providedPasswordHash)) {
                return true;
            } else {
                String invalidCachedPasswordHash = (String) getInvalidUsernameCache().get(username);
                if (invalidCachedPasswordHash != null && invalidCachedPasswordHash.equals(providedPasswordHash)) {
                    return false;
                }
            }
        }

        boolean logged = validateUsernamePassword(username, password);
        if (logged) {
            getGatewayUsernameCache().put(username, providedPasswordHash);
        } else {
            getInvalidUsernameCache().put(username, providedPasswordHash);
        }

        return logged;
    }

    public boolean validateScopes(String username, JSONObject resourceScopes, MessageContext synCtx) throws APISecurityException {
        if (resourceScopes != null) {
            String apiElectedResource = (String) synCtx.getProperty(APIConstants.API_ELECTED_RESOURCE);
            org.apache.axis2.context.MessageContext axis2MessageContext =
                    ((Axis2MessageContext) synCtx).getAxis2MessageContext();
            String httpMethod = (String) axis2MessageContext.getProperty(APIConstants.DigestAuthConstants.HTTP_METHOD);
            String resourceKey = apiElectedResource + ":" + httpMethod;

            String resourceCacheKey = resourceKey + ":" + username;
            String cachedResource = (String) getGatewayResourceCache().get(resourceCacheKey);
            if (cachedResource != null) {
                return true;
            } else {
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
                            getGatewayResourceCache().put(resourceCacheKey, resourceKey);
                            return true;
                        }
                    }
                } else {
//                      No scopes for the requested resource
                    getGatewayResourceCache().put(resourceCacheKey, resourceKey);
                    return true;
                }
            }
        } else {
//                  No scopes for API
            return true;
        }
        throw new APISecurityException(APISecurityConstants.INVALID_SCOPE, "Scope validation failed");
    }

    private String hashString(String str) {
        String generatedHash = null;
        try {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            //Add str bytes to digest
            md.update(str.getBytes());
            //Get the hash's bytes
            byte[] bytes = md.digest();
            //This bytes[] has bytes in decimal format;
            //Convert it to hexadecimal format
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            //Get complete hashed str in hex format
            generatedHash = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
        }
        return generatedHash;
    }

    private boolean validateUsernamePassword(String username, String password) throws APISecurityException {
        boolean logged;
        try {
            logged = remoteUserStoreManagerServiceStub.authenticate(username, password);
        } catch (Exception e) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, e.getMessage());
        }
        return logged;
    }

    protected Cache getGatewayResourceCache() {
        String apimGWCacheExpiry = getApiManagerConfiguration().getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);
        if (!gatewayResourceCacheInit) {
            gatewayResourceCacheInit = true;
            if (apimGWCacheExpiry != null) {
                return getCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_RESOURCE_CACHE_NAME, Long.parseLong(apimGWCacheExpiry), Long.parseLong(apimGWCacheExpiry));
            } else {
                long defaultCacheTimeout =
                        getDefaultCacheTimeout();
                return getCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_RESOURCE_CACHE_NAME, defaultCacheTimeout, defaultCacheTimeout);
            }
        }
        return getCacheFromCacheManager(APIConstants.GATEWAY_RESOURCE_CACHE_NAME);
    }

    protected Cache getGatewayUsernameCache() {
        String apimGWCacheExpiry = getApiManagerConfiguration().getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);
        if (!gatewayUsernameCacheInit) {
            gatewayUsernameCacheInit = true;
            if (apimGWCacheExpiry != null) {
                return getCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_USERNAME_CACHE_NAME, Long.parseLong(apimGWCacheExpiry), Long.parseLong(apimGWCacheExpiry));
            } else {
                long defaultCacheTimeout =
                        getDefaultCacheTimeout();
                return getCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_USERNAME_CACHE_NAME, defaultCacheTimeout, defaultCacheTimeout);
            }
        }
        return getCacheFromCacheManager(APIConstants.GATEWAY_USERNAME_CACHE_NAME);
    }

    protected Cache getCache(final String cacheManagerName, final String cacheName, final long modifiedExp,
                             long accessExp) {
        return APIUtil.getCache(cacheManagerName, cacheName, modifiedExp, accessExp);
    }

    protected APIManagerConfiguration getApiManagerConfiguration() {
        return ServiceReferenceHolder.getInstance().getAPIManagerConfiguration();
    }

    protected Cache getInvalidUsernameCache() {
        String apimGWCacheExpiry = getApiManagerConfiguration().
                getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);

        if (!gatewayInvalidUsernameCacheInit) {
            gatewayInvalidUsernameCacheInit = true;
            if (apimGWCacheExpiry != null) {
                return getCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_INVALID_USERNAME_CACHE_NAME,
                        Long.parseLong(apimGWCacheExpiry), Long.parseLong(apimGWCacheExpiry));
            } else {
                long defaultCacheTimeout = getDefaultCacheTimeout();
                return getCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_INVALID_USERNAME_CACHE_NAME,
                        defaultCacheTimeout, defaultCacheTimeout);
            }
        }
        return getCacheFromCacheManager(APIConstants.GATEWAY_INVALID_USERNAME_CACHE_NAME);
    }


    protected Cache getCacheFromCacheManager(String cacheName) {
        return Caching.getCacheManager(
                APIConstants.API_MANAGER_CACHE_MANAGER).getCache(cacheName);
    }

    protected long getDefaultCacheTimeout() {
        return Long.valueOf(ServerConfiguration.getInstance().getFirstProperty(APIConstants.DEFAULT_CACHE_TIMEOUT))
                * 60;
    }

    public boolean isGatewayTokenCacheEnabled() {
        try {
            APIManagerConfiguration config = getApiManagerConfiguration();
            String cacheEnabled = config.getFirstProperty(APIConstants.GATEWAY_TOKEN_CACHE_ENABLED);
            return Boolean.parseBoolean(cacheEnabled);
        } catch (Exception e) {
            log.error("Did not found valid API Validation Information cache configuration. Use default configuration" + e);
        }
        return true;
    }
}
