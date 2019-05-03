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

package org.wso2.carbon.apimgt.gateway.handlers.security.authenticator;

import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.Authenticator;
import org.wso2.carbon.apimgt.gateway.handlers.security.basic_auth.BasicAuthAuthenticator;
import org.wso2.carbon.apimgt.gateway.handlers.security.oauth.OAuthAuthenticator;
import org.wso2.carbon.apimgt.impl.APIConstants;

import java.util.*;


// Tests for multiple authentication scenario when having both oauth2 and basic auth enabled
public class MultiAuthenticatorTest {
    private MessageContext messageContext;
    private org.apache.axis2.context.MessageContext axis2MsgCntxt;
    private MultiAuthenticator multiAuthenticator;
    private final String CUSTOM_AUTH_HEADER = "AUTH-HEADER";


    @Before
    public void setup() {
        messageContext = Mockito.mock(Axis2MessageContext.class);
        axis2MsgCntxt = Mockito.mock(org.apache.axis2.context.MessageContext.class);
        Mockito.when(axis2MsgCntxt.getProperty(APIMgtGatewayConstants.REQUEST_RECEIVED_TIME)).thenReturn("1506576365");
        Mockito.when(((Axis2MessageContext) messageContext).getAxis2MessageContext()).thenReturn(axis2MsgCntxt);

        Map<String, Object> parametersForAuthenticator = new HashMap<>();
        parametersForAuthenticator.put(APIConstants.AUTHORIZATION_HEADER, HttpHeaders.AUTHORIZATION);
        parametersForAuthenticator.put(APIConstants.REMOVE_OAUTH_HEADERS_FROM_MESSAGE, true);
        parametersForAuthenticator.put(APIConstants.API_LEVEL_POLICY, null);
        parametersForAuthenticator.put(APIConstants.CERTIFICATE_INFORMATION, null);
        parametersForAuthenticator.put(APIConstants.API_SECURITY, "basic_auth,oauth2");
        multiAuthenticator = new MultiAuthenticator(parametersForAuthenticator);

        List<Authenticator> authenticatorList = new ArrayList<>();
        authenticatorList.add(new OAuthAuthenticator(CUSTOM_AUTH_HEADER, true){
            @Override
            public boolean authenticate(MessageContext synCtx) throws APISecurityException {
                Map headers = (Map) ((Axis2MessageContext) synCtx).getAxis2MessageContext().
                        getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
                String key = extractCustomerKeyFromAuthHeader(headers);
                if (key == null) {
                    throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_CREDENTIALS,
                            "No valid Authorization header found");
                } else if (key.equals("valid_oauth_key")) {
                    return true;
                } else {
                    throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_CREDENTIALS,
                            "Invalid access token");
                }
            }
        });
        authenticatorList.add(new BasicAuthAuthenticator(CUSTOM_AUTH_HEADER, true, null) {
            @Override
            public boolean authenticate(MessageContext synCtx) throws APISecurityException {
                String[] credentials = extractBasicAuthCredentials(synCtx);
                if (credentials[0].equals("valid_basic_auth_username") &&
                        credentials[1].equals("valid_basic_auth_password")) {
                    return true;
                }
                throw new APISecurityException(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                        "Authentication failed due to username & password mismatch");
            }
        });

        multiAuthenticator.setAuthenticatorList(authenticatorList);
    }

    @Test
    public void testAuthenticateWithValidOauthWithMissingBasicAuth() {
        TreeMap transportHeaders = new TreeMap();
        transportHeaders.put(CUSTOM_AUTH_HEADER, "Bearer valid_oauth_key");
        Mockito.when(axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(transportHeaders);

        try {
            Assert.assertTrue(multiAuthenticator.authenticate(messageContext));
        } catch (APISecurityException e) {
            Assert.fail();
        }
    }

    @Test
    public void testAuthenticateWithValidOauthWithInvalidBasicAuth() {
        TreeMap transportHeaders = new TreeMap();
        transportHeaders.put(CUSTOM_AUTH_HEADER, "Basic invalid_key, Bearer valid_oauth_key");
        Mockito.when(axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(transportHeaders);

        try {
            Assert.assertTrue(multiAuthenticator.authenticate(messageContext));
        } catch (APISecurityException e) {
            Assert.fail();
        }
    }

    @Test
    public void testAuthenticateWithInvalidOauthValidBasicAuth() {
        TreeMap transportHeaders = new TreeMap();
        // encode64('valid_basic_auth_username:valid_basic_auth_password)
        // = 'dmFsaWRfYmFzaWNfYXV0aF91c2VybmFtZTp2YWxpZF9iYXNpY19hdXRoX3Bhc3N3b3Jk'
        transportHeaders.put(CUSTOM_AUTH_HEADER,
                "Bearer invalid_oauth_key, Basic dmFsaWRfYmFzaWNfYXV0aF91c2VybmFtZTp2YWxpZF9iYXNpY19hdXRoX3Bhc3N3b3Jk");
        Mockito.when(axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(transportHeaders);

        try {
            Assert.assertTrue(multiAuthenticator.authenticate(messageContext));
        } catch (APISecurityException e) {
            Assert.fail();
        }
    }

    @Test
    public void testAuthenticateWithMissingOauthValidBasicAuth() {
        TreeMap transportHeaders = new TreeMap();
        // encode64('valid_basic_auth_username:valid_basic_auth_password)
        // = 'dmFsaWRfYmFzaWNfYXV0aF91c2VybmFtZTp2YWxpZF9iYXNpY19hdXRoX3Bhc3N3b3Jk'
        transportHeaders.put(CUSTOM_AUTH_HEADER,
                "Basic dmFsaWRfYmFzaWNfYXV0aF91c2VybmFtZTp2YWxpZF9iYXNpY19hdXRoX3Bhc3N3b3Jk");
        Mockito.when(axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(transportHeaders);

        try {
            Assert.assertTrue(multiAuthenticator.authenticate(messageContext));
        } catch (APISecurityException e) {
            Assert.fail();
        }
    }

    @Test
    public void testAuthenticateWithInvalidOauthInvalidBasicAuth() {
        TreeMap transportHeaders = new TreeMap();
        transportHeaders.put(CUSTOM_AUTH_HEADER, "Basic invalid, Bearer invalid");
        Mockito.when(axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(transportHeaders);

        try {
            Assert.assertTrue(multiAuthenticator.authenticate(messageContext));
            Assert.fail();
        } catch (APISecurityException e) {
            Assert.assertEquals(e.getErrorCode(), APISecurityConstants.API_AUTH_INVALID_CREDENTIALS);
        }
    }

    @Test
    public void testAuthenticateWithMissingOauthMissingBasicAuth() {
        TreeMap transportHeaders = new TreeMap();
        Mockito.when(axis2MsgCntxt.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS)).thenReturn(transportHeaders);

        try {
            Assert.assertTrue(multiAuthenticator.authenticate(messageContext));
            Assert.fail();
        } catch (APISecurityException e) {
            Assert.assertEquals(e.getErrorCode(), APISecurityConstants.API_AUTH_MISSING_BASIC_AUTH_AND_OAUTH_CREDENTIALS);
        }
    }
}