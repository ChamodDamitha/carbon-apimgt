/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.apimgt.gateway.handlers.security.authenticator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.Authenticator;
import org.wso2.carbon.apimgt.gateway.handlers.security.basic_auth.BasicAuthAuthenticator;
import org.wso2.carbon.apimgt.gateway.handlers.security.oauth.OAuthAuthenticator;
import org.wso2.carbon.apimgt.impl.APIConstants;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator responsible for handling multiple authenticators.
 */
public class MultiAuthenticator implements Authenticator {
    private static final Log log = LogFactory.getLog(MultiAuthenticator.class);
    private volatile List<Authenticator> authenticatorList;
    private String apiSecurity;
    private String authorizationHeader;
    private boolean removeOAuthHeadersFromOutMessage;
    private Map<String, Object> parameters;
    private static List<SecurityProtocol> supportedSecurityProtocols;

    private final String basicAuthKeyHeaderSegment = "Basic";
    private final String oauthKeyHeaderSegment = "Bearer";
    private final String authHeaderSplitter = ",";

    static {
        supportedSecurityProtocols = new ArrayList<>();
        supportedSecurityProtocols
                .add(new SecurityProtocol(APIConstants.API_SECURITY_MUTUAL_SSL, MutualSSLAuthenticator.class.getName(),
                        new String[] { APIConstants.API_LEVEL_POLICY, APIConstants.CERTIFICATE_INFORMATION },
                        new Class[] { String.class, String.class }));
        supportedSecurityProtocols
                .add(new SecurityProtocol(APIConstants.DEFAULT_API_SECURITY_OAUTH2, OAuthAuthenticator.class.getName(),
                        new String[] { APIConstants.AUTHORIZATION_HEADER,
                                APIConstants.REMOVE_OAUTH_HEADERS_FROM_MESSAGE },
                        new Class[] { String.class, boolean.class }));
        supportedSecurityProtocols
                .add(new SecurityProtocol(APIConstants.API_SECURITY_BASIC_AUTH, BasicAuthAuthenticator.class.getName(),
                        new String[] { APIConstants.AUTHORIZATION_HEADER,
                                APIConstants.REMOVE_OAUTH_HEADERS_FROM_MESSAGE, "resourceScopes" },
                        new Class[] { String.class, boolean.class, String.class }));
    }

    /**
     * Initialize the authenticator with the required parameters.
     *
     * @param parameters Relevant parameters needed to initialize the authenticators.
     */
    public MultiAuthenticator(Map<String, Object> parameters) {
        apiSecurity = (String) parameters.get(APIConstants.API_SECURITY);
        authorizationHeader = (String) parameters.get(APIConstants.AUTHORIZATION_HEADER);
        removeOAuthHeadersFromOutMessage = (Boolean) parameters.get(APIConstants.REMOVE_OAUTH_HEADERS_FROM_MESSAGE);
        this.parameters = parameters;
    }

    protected void setAuthenticatorList(List<Authenticator> authenticatorList) {
        this.authenticatorList = authenticatorList;
    }

    @Override
    public void init(SynapseEnvironment env) {
        if (authenticatorList == null || authenticatorList.size() == 0) {
            authenticatorList = new ArrayList<>();
            for (SecurityProtocol supportedSecurityProtocol : supportedSecurityProtocols) {
                String authenticatorClassName = supportedSecurityProtocol.getAuthenticatorClassName();
                String authenticatorProtocolName = supportedSecurityProtocol.getProtocolName();
                try {
                    if (apiSecurity.contains(authenticatorProtocolName)) {
                        String[] parameterList = supportedSecurityProtocol.getListOfParameters();
                        Class[] parameterTypes = supportedSecurityProtocol.getParameterTypes();
                        Object[] authenticatorParameters = new Object[parameterList.length];
                        for (int index = 0; index < parameterList.length; index++) {
                            authenticatorParameters[index] = parameters.get(parameterList[index]);
                        }
                        Class<?> authenticatorClass = Class.forName(authenticatorClassName);
                        Constructor<?> constructor = authenticatorClass.getConstructor(parameterTypes);
                        Authenticator authenticator = (Authenticator) constructor.newInstance(authenticatorParameters);
                        authenticator.init(env);
                        authenticatorList.add(authenticator);
                    }
                } catch (ClassNotFoundException e) {
                    log.error(authenticatorClassName + " is not available in the "
                            + "environment, hence not adding the authenticator " + authenticatorProtocolName, e);
                } catch (NoSuchMethodException e) {
                    log.error(authenticatorClassName + " does not have the "
                            + "constructor that supports the provided parameters, hence not adding the authenticator "
                            + authenticatorProtocolName, e);
                } catch (InstantiationException e) {
                    log.error("Error while trying to instantiate the authenticator " + authenticatorProtocolName, e);
                } catch (IllegalAccessException e) {
                    log.error(authenticatorClassName + "'s constructor is not "
                            + "accessible from MultiAuthenticator.hence not adding the authenticator "
                            + authenticatorProtocolName, e);
                } catch (InvocationTargetException e) {
                    log.error("Invocation target exception while trying to add the auth.hence not adding the "
                            + "authenticator " + authenticatorProtocolName, e);
                }
            }
        }
    }

    @Override
    public void destroy() {
        if (authenticatorList == null) {
            for (Authenticator authenticator : authenticatorList) {
                authenticator.destroy();
            }
            authenticatorList = null;
        } else {
            log.warn("Authenticator list is empty. Nothing to destroy");
        }
    }

    @Override
    public boolean authenticate(MessageContext synCtx) throws APISecurityException {
        boolean isAuthenticated = false;
        String errorMessage = "";
        APISecurityException apiSecurityException = null;
        int apiSecurityErrorCode = 0;

        int i = 0;
        Authenticator firstAuthenticator = authenticatorList.get(0);

        if (firstAuthenticator instanceof MutualSSLAuthenticator) {
            try {
                boolean isSSLAuthenticated = firstAuthenticator.authenticate(synCtx);
                if (isSSLAuthenticated) {
                    if (authenticatorList.size() > 1) {
                        // To authenticate using next authenticator onwards
                        i = 1;
                    } else {
                        isAuthenticated = true;
                        // stop authenticating using other authenticators
                        i = authenticatorList.size();
                    }
                } else {
                    // stop authenticating using other authenticators
                    i = authenticatorList.size();
                }
            } catch (APISecurityException ex) {
                if (StringUtils.isNotEmpty(errorMessage)) {
                    errorMessage += " and ";
                }
                errorMessage += ex.getMessage();

                // stop authenticating using other authenticators
                i = authenticatorList.size();
            }
        }

        // if i = 0 , not Mutual SSL protected. Therefore, start from first authenticator onwards to authenticate
        for (int index = i; !isAuthenticated && index < authenticatorList.size(); index++) {
            Authenticator authenticator = authenticatorList.get(index);
            try {
                isAuthenticated = authenticator.authenticate(synCtx);
            } catch (APISecurityException ex) {
                // This is to maintain the backward compatibility between error codes when using OAuth2Authenticator.
                if ((authenticator instanceof OAuthAuthenticator) || (authenticator instanceof BasicAuthAuthenticator)) {
                    if (ex.getErrorCode() == APISecurityConstants.API_AUTH_MISSING_CREDENTIALS) {
                        apiSecurityErrorCode = APISecurityConstants.API_AUTH_MISSING_CREDENTIALS;
                    } else if (ex.getErrorCode() == APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_CREDENTIALS) {
                        if (apiSecurityErrorCode == APISecurityConstants.API_AUTH_MISSING_CREDENTIALS) {
                            apiSecurityErrorCode = APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_AND_OAUTH_CREDENTIALS;
                        } else {
                            apiSecurityErrorCode = APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_CREDENTIALS;
                        }
                    } else {
                        apiSecurityException = ex;
                    }
                }
                if (StringUtils.isNotEmpty(errorMessage)) {
                    errorMessage += " and ";
                }
                errorMessage += ex.getMessage();
            }
        }

        if (!isAuthenticated) {
            if (apiSecurityException != null) {
                throw apiSecurityException;
            } else if (apiSecurityErrorCode != 0) {
                throw new APISecurityException(apiSecurityErrorCode, errorMessage);
            } else if (StringUtils.isNotEmpty(errorMessage)) {
                throw new APISecurityException(APISecurityConstants.MULTI_AUTHENTICATION_FAILURE, errorMessage);
            }
        }
        //Update auth header
        updateAuthHeader(synCtx);

        return isAuthenticated;
    }

    private void updateAuthHeader(MessageContext synCtx) {
        Map headers = (Map) ((Axis2MessageContext) synCtx).getAxis2MessageContext().
                getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null) {
            String authHeader = (String) headers.get(authorizationHeader);
            if (authHeader != null) {
                String[] tempAuthHeader = authHeader.split(authHeaderSplitter);
                String remainingAuthHeader = "";
                for (int i = 0; i < tempAuthHeader.length; i++) {
                    String h = tempAuthHeader[i];
                    if (h.trim().startsWith(basicAuthKeyHeaderSegment) &&
                            apiSecurity.contains(APIConstants.API_SECURITY_BASIC_AUTH)) {
                        //If basic auth header is sent for the basic auth validation at the gateway, remove it
                        continue;
                    } else if (h.trim().startsWith(oauthKeyHeaderSegment) && removeOAuthHeadersFromOutMessage) {
                        //If oauth header is configured to be removed at the gateway, remove it
                        continue;
                    }
                    remainingAuthHeader += h;
                    if (i < tempAuthHeader.length - 1) {
                        remainingAuthHeader += authHeaderSplitter;
                    }
                }
                //Remove authorization headers sent for authentication at the gateway and pass others to the backend
                if (remainingAuthHeader != "") {
                    headers.put(authorizationHeader, remainingAuthHeader);
                } else {
                    headers.remove(authorizationHeader);
                }
            }
        }
    }

    @Override
    public String getChallengeString() {
        StringBuilder challengeString = new StringBuilder();
        if (authenticatorList != null) {
            for (Authenticator authenticator : authenticatorList) {
                challengeString.append(authenticator.getChallengeString()).append(" ");
            }
        }
        return challengeString.toString().trim();
    }

    @Override
    public String getRequestOrigin() {
        String requestOrigin = "";

        if (authenticatorList != null) {
            for (int index = 0; requestOrigin.isEmpty() && index < authenticatorList.size(); index++) {
                Authenticator authenticator = authenticatorList.get(index);
                requestOrigin = authenticator.getRequestOrigin();
            }
        }
        return requestOrigin;
    }
}
