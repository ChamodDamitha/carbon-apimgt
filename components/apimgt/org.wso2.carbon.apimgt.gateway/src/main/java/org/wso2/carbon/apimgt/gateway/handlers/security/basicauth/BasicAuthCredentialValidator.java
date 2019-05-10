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

package org.wso2.carbon.apimgt.gateway.handlers.security.basicauth;


import io.swagger.models.Path;
import io.swagger.models.Swagger;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
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

/**
 * This class will validate the basic auth credentials.
 */
public class BasicAuthCredentialValidator {

    private boolean gatewayKeyCacheEnabled;
    private static boolean gatewayUsernameCacheInit = false;
    private static boolean gatewayResourceCacheInit = false;

    protected Log log = LogFactory.getLog(getClass());
    private RemoteUserStoreManagerServiceStub remoteUserStoreManagerServiceStub;

    /**
     * Initialize the validator.
     */
    public BasicAuthCredentialValidator() {}

    /**
     * Initialize the validator with the synapse environment.
     *
     * @param env the synapse environment
     * @throws APISecurityException If an authentication failure or some other error occurs
     */
    public BasicAuthCredentialValidator(SynapseEnvironment env) throws APISecurityException {
        this.gatewayKeyCacheEnabled = isGatewayTokenCacheEnabled();
        this.getGatewayUsernameCache();

        ConfigurationContext configurationContext = ServiceReferenceHolder.getInstance().getAxis2ConfigurationContext();
        APIManagerConfiguration config = HostObjectComponent.getAPIManagerConfiguration();
        String url = config.getFirstProperty(APIConstants.AUTH_MANAGER_URL);//TODO:key validator url
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

    /**
     * Validates the given username and password against the users in the user store.
     *
     * @param username given username
     * @param password given password
     * @return true if the validation passed
     * @throws APISecurityException If an authentication failure or some other error occurs
     */
    public boolean validate(String username, String password) throws APISecurityException { //TODO:observability
        String providedPasswordHash = hashString(password);//TODO:move inside  // password -> Char array
        if (gatewayKeyCacheEnabled) {
            String cachedPasswordHash = (String) getGatewayUsernameCache().get(username);
            if (cachedPasswordHash != null && cachedPasswordHash.equals(providedPasswordHash)) {
                return true; //If (username->password) is in the valid cache
            } else {
                String invalidCachedPasswordHash = (String) getInvalidUsernameCache().get(username);
                if (invalidCachedPasswordHash != null && invalidCachedPasswordHash.equals(providedPasswordHash)) {
                    return false; //If (username->password) is in the invalid cache
                }
            }
        }

        boolean authenticated;
        try {
            authenticated = remoteUserStoreManagerServiceStub.authenticate(username, password);
        } catch (Exception e) {
            throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, e.getMessage());
        }

        //TODO: check cache enabled
        if (authenticated) {
            // put (username->password) into the valid cache
            getGatewayUsernameCache().put(username, providedPasswordHash);
        } else {
            // put (username->password) into the invalid cache
            getInvalidUsernameCache().put(username, providedPasswordHash);
        }

        return authenticated;
    }

    /**
     * Validates the roles of the given user against the roles of the scopes of the API resource.
     *
     * @param username given username
     * @param swagger swagger of the API
     * @param synCtx The message to be authenticated
     * @return true if the validation passed
     * @throws APISecurityException If an authentication failure or some other error occurs
     */
    public boolean validateScopes(String username, Swagger swagger, MessageContext synCtx) throws APISecurityException {
        if (swagger != null) {
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
                // retrieve the user roles related to the scope of the API resource
                String resource_roles = null;//TODO: use camel case
                Path path = swagger.getPath(apiElectedResource);
                if (path != null) {
                    if (httpMethod.equals("GET")) {//TODO:use constants
                        resource_roles = (String) path.getGet().getVendorExtensions().get(APIConstants.SWAGGER_X_ROLES);
                    } else if (httpMethod.equals("POST")) {
                        resource_roles = (String) path.getPost().getVendorExtensions().get(APIConstants.SWAGGER_X_ROLES);
                    } else if (httpMethod.equals("PUT")) {
                        resource_roles = (String) path.getPut().getVendorExtensions().get(APIConstants.SWAGGER_X_ROLES);
                    } else if (httpMethod.equals("DELETE")) {
                        resource_roles = (String) path.getDelete().getVendorExtensions().get(APIConstants.SWAGGER_X_ROLES);
                    }
                }
                if (resource_roles != null && resource_roles.trim() != "") { //TODO:string utils
                    String[] user_roles;
                    try {
                        user_roles = remoteUserStoreManagerServiceStub.getRoleListOfUser(username);
                    } catch (Exception e) {
                        throw new APISecurityException(APISecurityConstants.API_AUTH_GENERAL_ERROR, e.getMessage());
                    }
                    // check if the roles related to the API resource contains any of the role of the user
                    for (String role : user_roles) {
                        if (resource_roles.contains(role)) {
                            getGatewayResourceCache().put(resourceCacheKey, resourceKey);
                            return true;
                        }
                    }
                } else {
                    // No scopes for the requested resource
                    getGatewayResourceCache().put(resourceCacheKey, resourceKey);
                    return true;
                }
            }
        } else {
            // No scopes for API
            return true;
        }
        throw new APISecurityException(APISecurityConstants.INVALID_SCOPE, "Scope validation failed");
    }

    /**
     * Returns the md5 hash of a given string.
     *
     * @param str the string input to be hashed
     * @return hashed string
     */
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

    /**
     * Returns the resource request cache.
     *
     * @return the resource cache
     */
    private Cache getGatewayResourceCache() { //TODO: method name
        String apimGWCacheExpiry = getApiManagerConfiguration().getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);
        if (!gatewayResourceCacheInit) {
            gatewayResourceCacheInit = true;
            if (apimGWCacheExpiry != null) {
                return createCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_RESOURCE_CACHE_NAME,
                        Long.parseLong(apimGWCacheExpiry), Long.parseLong(apimGWCacheExpiry));
            } else {
                long defaultCacheTimeout =
                        getDefaultCacheTimeout();
                return createCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_RESOURCE_CACHE_NAME,
                        defaultCacheTimeout, defaultCacheTimeout);
            }
        }
        return getCacheFromCacheManager(APIConstants.GATEWAY_RESOURCE_CACHE_NAME);
    }

    /**
     * Returns the valid username cache.
     *
     * @return the valid username cache
     */
    private Cache getGatewayUsernameCache() {
        String apimGWCacheExpiry = getApiManagerConfiguration().getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);
        if (!gatewayUsernameCacheInit) {
            gatewayUsernameCacheInit = true;
            if (apimGWCacheExpiry != null) {
                return createCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_USERNAME_CACHE_NAME,
                        Long.parseLong(apimGWCacheExpiry), Long.parseLong(apimGWCacheExpiry));
            } else {
                long defaultCacheTimeout =
                        getDefaultCacheTimeout();
                return createCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_USERNAME_CACHE_NAME,
                        defaultCacheTimeout, defaultCacheTimeout);
            }
        }
        return getCacheFromCacheManager(APIConstants.GATEWAY_USERNAME_CACHE_NAME);
    }

    /**
     * Returns the invalid username cache.
     *
     * @return the invalid username cache
     */
    private Cache getInvalidUsernameCache() {
        String apimGWCacheExpiry = getApiManagerConfiguration().
                getFirstProperty(APIConstants.TOKEN_CACHE_EXPIRY);

        if (!gatewayUsernameCacheInit) {
            gatewayUsernameCacheInit = true;
            if (apimGWCacheExpiry != null) {
                return createCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_INVALID_USERNAME_CACHE_NAME,
                        Long.parseLong(apimGWCacheExpiry), Long.parseLong(apimGWCacheExpiry));
            } else {
                long defaultCacheTimeout = getDefaultCacheTimeout();
                return createCache(APIConstants.API_MANAGER_CACHE_MANAGER, APIConstants.GATEWAY_INVALID_USERNAME_CACHE_NAME,
                        defaultCacheTimeout, defaultCacheTimeout);
            }
        }
        return getCacheFromCacheManager(APIConstants.GATEWAY_INVALID_USERNAME_CACHE_NAME);
    }

    /**
     * Create the Cache object from the given parameters.
     *
     * @param cacheManagerName name of the cache manager
     * @param cacheName name of the Cache
     * @param modifiedExp value of the modified expiry type
     * @param accessExp value of the accessed expiry type
     * @return the cache object
     */
    private Cache createCache(final String cacheManagerName, final String cacheName, final long modifiedExp,
                              long accessExp) {
        return APIUtil.getCache(cacheManagerName, cacheName, modifiedExp, accessExp);
    }

    /**
     * Returns the API Manager Configuration.
     *
     * @return the API Manager Configuration
     */
    private APIManagerConfiguration getApiManagerConfiguration() {
        return ServiceReferenceHolder.getInstance().getAPIManagerConfiguration();
    }

    /**
     * Returns the Cache object of the given name.
     *
     * @param cacheName name of the Cache
     * @return the cache object
     */
    private Cache getCacheFromCacheManager(String cacheName) {
        return Caching.getCacheManager(
                APIConstants.API_MANAGER_CACHE_MANAGER).getCache(cacheName);
    }

    /**
     * Returns the default cache timeout.
     *
     * @return the default cache timeout
     */
    private long getDefaultCacheTimeout() {
        return Long.valueOf(ServerConfiguration.getInstance().getFirstProperty(APIConstants.DEFAULT_CACHE_TIMEOUT))
                * 60;
    }

    /**
     * Returns whether the gateway token cache is enabled.
     *
     * @return true if the gateway token cache is enabled
     */
    private boolean isGatewayTokenCacheEnabled() { //TODO:move to util
        try {
            APIManagerConfiguration config = getApiManagerConfiguration();
            String cacheEnabled = config.getFirstProperty(APIConstants.GATEWAY_TOKEN_CACHE_ENABLED);
            return Boolean.parseBoolean(cacheEnabled);
        } catch (Exception e) {
            log.error("Did not found valid API Validation Information cache configuration." +
                    " Use default configuration" + e);
        }
        return true;
    }
}
