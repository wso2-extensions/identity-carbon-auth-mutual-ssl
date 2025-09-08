/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.mutualssl;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.identity.authenticator.mutualssl.internal.MutualSSLAuthenticatorServiceComponent;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
public class MutualSSLAuthenticatorTest {

    @Mock
    private MessageContext messageContext;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpSession httpSession;

    @Mock
    private SOAPEnvelope soapEnvelope;

    @Mock
    private SOAPHeader soapHeader;

    @Mock
    private SOAPHeaderBlock soapHeaderBlock;

    @Mock
    private X509Certificate x509Certificate;

    @Mock
    private RealmService realmService;

    @Mock
    private TenantManager tenantManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UserStoreManager userStoreManager;

    private MutualSSLAuthenticator mutualSSLAuthenticator;

    @BeforeClass
    public void init() {

        MockitoAnnotations.initMocks(this);
        mutualSSLAuthenticator = new MutualSSLAuthenticator();
    }

    @BeforeMethod
    public void setUp() throws Exception {

        // Reset static state before each test to avoid interference between tests.
        resetMutualSSLAuthenticatorStaticState();

        // Reset all mocks to clear any previous interactions.
        reset(messageContext, httpServletRequest, httpSession, soapEnvelope, soapHeader,
                soapHeaderBlock, x509Certificate, realmService, tenantManager, userRealm, userStoreManager);

        // Setup common mocks.
        when(messageContext.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST)).thenReturn(httpServletRequest);
        when(messageContext.getEnvelope()).thenReturn(soapEnvelope);
        when(soapEnvelope.getHeader()).thenReturn(soapHeader);
        when(httpServletRequest.getSession()).thenReturn(httpSession);
    }

    /**
     * Reset all static state in MutualSSLAuthenticator to ensure test isolation
     */
    private void resetMutualSSLAuthenticatorStaticState() throws Exception {

        Class<?> authClass = MutualSSLAuthenticator.class;

        // Reset static fields using reflection.
        setStaticField(authClass, "usernameHeaderName", "UserName");
        setStaticField(authClass, "whiteList", null);
        setStaticField(authClass, "whiteListEnabled", false);
        setStaticField(authClass, "authenticatorInitialized", false);
        setStaticField(authClass, "enableSHA256CertificateThumbprint", true);

        // Reset static collections.
        resetStaticCollection(authClass, "thumbprintUserMapping");
        resetStaticCollection(authClass, "certIssuerToUserMapping");
        resetStaticCollection(authClass, "allowedIssuers");
    }

    /**
     * Helper method to set static field values using reflection
     */
    private void setStaticField(Class<?> clazz, String fieldName, Object value) throws Exception {

        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(null, value);
    }

    /**
     * Helper method to clear static collections using reflection
     */
    private void resetStaticCollection(Class<?> clazz, String fieldName) throws Exception {

        Field field = clazz.getDeclaredField(fieldName);
        field.setAccessible(true);
        Object collection = field.get(null);
        if (collection instanceof java.util.Map) {
            ((java.util.Map<?, ?>) collection).clear();
        } else if (collection instanceof java.util.Set) {
            ((java.util.Set<?>) collection).clear();
        }
    }

    // Helper method to create standard configuration with allowed issuers.
    private java.util.Map<String, String> createConfigWithAllowedIssuers(String issuerDN) {

        java.util.Map<String, String> configParams = new java.util.HashMap<>();
        configParams.put("allowed_issuers", issuerDN);
        configParams.put("issuer_" + issuerDN, "*"); // Allow any username for this issuer.
        return configParams;
    }

    // Helper method to create thumbprint mapping configuration.
    private java.util.Map<String, String> createThumbprintMappingConfig(String issuerDN, String thumbprint, String users) {

        java.util.Map<String, String> configParams = new java.util.HashMap<>();
        configParams.put("allowed_issuers", issuerDN);
        configParams.put("cert_thumbprint_" + thumbprint, users);
        return configParams;
    }

    // Helper method to setup mock authentication configuration.
    private void setupMockAuthConfig(java.util.Map<String, String> configParams,
                                   MockedStatic<AuthenticatorsConfiguration> authConfigMock) {

        AuthenticatorsConfiguration mockAuthConfig = mock(AuthenticatorsConfiguration.class);
        AuthenticatorsConfiguration.AuthenticatorConfig mockConfig = mock(AuthenticatorsConfiguration.AuthenticatorConfig.class);
        authConfigMock.when(AuthenticatorsConfiguration::getInstance).thenReturn(mockAuthConfig);
        when(mockAuthConfig.getAuthenticatorConfig("MutualSSLAuthenticator")).thenReturn(mockConfig);
        when(mockConfig.getParameters()).thenReturn(configParams);
    }

    // Helper method to setup basic certificate and context mocks.
    private void setupBasicCertificateMocks(String username) throws CertificateEncodingException {

        X509Certificate[] certificates = {x509Certificate};
        when(httpServletRequest.getAttribute("javax.servlet.request.X509Certificate")).thenReturn(certificates);
        when(x509Certificate.getEncoded()).thenReturn("test_cert_data".getBytes());

        javax.security.auth.x500.X500Principal issuerPrincipal = new javax.security.auth.x500.X500Principal("CN=Test Issuer, O=Test Org, C=US");
        when(x509Certificate.getIssuerDN()).thenReturn(issuerPrincipal);

        String encodedUsername = org.apache.axiom.om.util.Base64.encode(username.getBytes(StandardCharsets.UTF_8));
        when(httpServletRequest.getHeader("UserName")).thenReturn(encodedUsername);
    }

    // Helper method to setup static dependencies and realm service.
    private void setupStaticDependencies(String username, String tenantDomain,
                                        MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock,
                                        MockedStatic<MultitenantUtils> tenantUtilsMock) throws UserStoreException {

        serviceComponentMock.when(MutualSSLAuthenticatorServiceComponent::getRealmService).thenReturn(realmService);
        tenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(username)).thenReturn(tenantDomain);
        tenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(username)).thenReturn(
            username.contains("@") ? username.split("@")[0] : username);

        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(tenantDomain)).thenReturn(1);
        when(realmService.getTenantUserRealm(1)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(username.contains("@") ? username.split("@")[0] : username)).thenReturn(true);
    }

    // Test Data Providers
    @DataProvider(name = "validUsernames")
    public Object[][] validUsernames() {

        return new Object[][]{
                {"testuser", "testuser", "carbon.super"},
                {"admin@tenant.com", "admin", "tenant.com"},
                {"user@example.org", "user", "example.org"}
        };
    }

    // Test Case 1: No Username Found in Headers.
    @Test(description = "Test authentication fails when no username is found in HTTP or SOAP headers")
    public void testNoUsernameFound() throws Exception {
        
        resetMutualSSLAuthenticatorStaticState();

        // Mock empty HTTP header.
        when(httpServletRequest.getHeader("UserName")).thenReturn(null);
        when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

        // Mock SOAP envelope and header.
        when(messageContext.getEnvelope()).thenReturn(soapEnvelope);
        when(soapEnvelope.getHeader()).thenReturn(soapHeader);
        when(soapHeader.getHeaderBlocksWithNSURI("http://mutualssl.carbon.wso2.org")).thenReturn(null);

        boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
        assertFalse(result, "Authentication should fail when no username is found");
    }

    // Test Case 2: Valid Username in HTTP Header.
    @Test(dataProvider = "validUsernames", description = "Test authentication succeeds with valid username " +
            "in HTTP header and wildcard issuer mapping")
    public void testValidUsernameInHeader(String inputUsername, String expectedUsername, String expectedTenantDomain) throws Exception {

        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks(inputUsername);

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock =
                     Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            java.util.Map<String, String> configParams = createConfigWithAllowedIssuers(
                    "CN=Test Issuer, O=Test Org, C=US");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies(inputUsername, expectedTenantDomain, serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            // Mock the authentication utility call.
            authUtilMock.when(() -> CarbonAuthenticationUtil.onSuccessAdminLogin(
                    any(HttpSession.class), eq(expectedUsername), eq(1), eq(expectedTenantDomain),
                    eq("Mutual SSL Authentication"))).then(invocation -> {
                HttpSession session = invocation.getArgument(0);
                session.setAttribute("USERNAME", expectedUsername);
                session.setAttribute("TENANT_DOMAIN", expectedTenantDomain);
                return null;
            });

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertTrue(result, "Authentication should succeed with valid username and trusted issuer");

            // Verify session attributes were set correctly.
            verify(httpSession).setAttribute("USERNAME", expectedUsername);
            verify(httpSession).setAttribute("TENANT_DOMAIN", expectedTenantDomain);
        }
    }

    // Test Case 3: Authentication fails with invalid configurations
    @Test(description = "Test authentication fails with invalid configurations")
    public void testInvalidConfigurations() throws Exception {
        
        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("testuser");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock =
                     Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            // Empty configuration - no allowed issuers.
            java.util.Map<String, String> configParams = new java.util.HashMap<>();
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("testuser", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertFalse(result, "Authentication should fail with invalid configurations");
        }
    }

    // Test Case 4: Whitelist validation with wrong thumbprint.
    @Test(description = "Test authentication fails when whitelist is enabled but certificate thumbprint is not in whitelist")
    public void testWhitelistWrongThumbprint() throws Exception {

        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("testuser");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            // Create config with whitelist enabled but wrong thumbprint
            java.util.Map<String, String> configParams = new java.util.HashMap<>();
            configParams.put("WhiteListEnabled", "true");
            configParams.put("WhiteList", "wrongthumbprint1,wrongthumbprint2");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("testuser", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertFalse(result, "Authentication should fail when certificate thumbprint is not in whitelist");
        }
    }

    // Test Case 5: Whitelist validation with correct thumbprint.
    @Test(description = "Test authentication succeeds when whitelist is enabled and certificate thumbprint is in whitelist")
    public void testWhitelistCorrectThumbprint() throws Exception {

        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("testuser");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock =
                     Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            // Create config with whitelist enabled and correct thumbprint.
            java.util.Map<String, String> configParams = new java.util.HashMap<>();
            configParams.put("WhiteListEnabled", "true");
            configParams.put("WhiteList", "96b24ad9d755125139cd790189a54f4ef2241b9b3cc44b5949fa8921527c62f5");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("testuser", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            // Mock the authentication utility call.
            authUtilMock.when(() -> CarbonAuthenticationUtil.onSuccessAdminLogin(
                    any(HttpSession.class), eq("testuser"), eq(1), eq("carbon.super"),
                    eq("Mutual SSL Authentication"))).then(invocation -> {
                HttpSession session = invocation.getArgument(0);
                session.setAttribute("USERNAME", "testuser");
                session.setAttribute("TENANT_DOMAIN", "carbon.super");
                return null;
            });

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertTrue(result, "Authentication should succeed when certificate thumbprint is in whitelist");

            verify(httpSession).setAttribute("USERNAME", "testuser");
            verify(httpSession).setAttribute("TENANT_DOMAIN", "carbon.super");
        }
    }

    // Test Case 6: Issuer DN mapping allows admin user.
    @Test(description = "Test authentication succeeds when issuer DN mapping allows specific admin user")
    public void testIssuerDNMappingAdminUser() throws Exception {

        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("admin");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock = 
                Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock = 
                Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock = 
                Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock = 
                Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            // Create config with issuer DN that only allows admin user
            java.util.Map<String, String> configParams = createConfigWithAllowedIssuers("CN=Test Issuer, O=Test Org, C=US");
            configParams.put("issuer_CN=Test Issuer, O=Test Org, C=US", "admin");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("admin", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            // Mock the authentication utility call.
            authUtilMock.when(() -> CarbonAuthenticationUtil.onSuccessAdminLogin(
                    any(HttpSession.class), eq("admin"), eq(1), eq("carbon.super"), 
                    eq("Mutual SSL Authentication"))).then(invocation -> {
                        HttpSession session = invocation.getArgument(0);
                        session.setAttribute("USERNAME", "admin");
                        session.setAttribute("TENANT_DOMAIN", "carbon.super");
                        return null;
                    });

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertTrue(result, "Authentication should succeed for admin user with allowed issuer DN mapping");

            verify(httpSession).setAttribute("USERNAME", "admin");
            verify(httpSession).setAttribute("TENANT_DOMAIN", "carbon.super");
        }
    }

    // Test Case 7: Issuer DN mapping denies unauthorized user.
    @Test(description = "Test authentication fails when issuer DN mapping denies unauthorized user")
    public void testIssuerDNMappingUnauthorizedUser() throws Exception {

        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("user1");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock = 
                Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock = 
                Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock = 
                Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock = 
                Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            // Create config with issuer DN that only allows admin user (NOT user1)
            java.util.Map<String, String> configParams = createConfigWithAllowedIssuers("CN=Test Issuer, O=Test Org, C=US");
            configParams.put("issuer_CN=Test Issuer, O=Test Org, C=US", "admin");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("user1", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertFalse(result, "Authentication should fail for user1 as it's not in the allowed issuer DN mapping");
        }
    }

    // Test Case 8: Thumbprint mapping allows admin user
    @Test(description = "Test authentication succeeds when valid thumbprint mapping is configured for admin user")
    public void testThumbprintMappingAdminUser() throws Exception {
        
        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("admin");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock =
                     Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            java.util.Map<String, String> configParams = createThumbprintMappingConfig("CN=Test Issuer, O=Test Org, C=US",
                    "96b24ad9d755125139cd790189a54f4ef2241b9b3cc44b5949fa8921527c62f5",
                    "admin,user2");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("admin", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertTrue(result, "Authentication should succeed for admin user with valid thumbprint mapping");
        }
    }

    // Test Case 9: Thumbprint mapping allows user2
    @Test(description = "Test authentication succeeds when valid thumbprint mapping is configured for user2")
    public void testThumbprintMappingUser2() throws Exception {
        
        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("user2");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock =
                     Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            java.util.Map<String, String> configParams = createThumbprintMappingConfig("CN=Test Issuer, O=Test Org, C=US",
                    "96b24ad9d755125139cd790189a54f4ef2241b9b3cc44b5949fa8921527c62f5",
                    "admin,user2");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("user2", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertTrue(result, "Authentication should succeed for user2 with valid thumbprint mapping");
        }
    }

    // Test Case 10: Thumbprint mapping denies unauthorized user
    @Test(description = "Test authentication fails when user is not in thumbprint mapping")
    public void testThumbprintMappingUnauthorizedUser() throws Exception {
        
        resetMutualSSLAuthenticatorStaticState();
        setupBasicCertificateMocks("unauthorizeduser");

        try (MockedStatic<MutualSSLAuthenticatorServiceComponent> serviceComponentMock =
                     Mockito.mockStatic(MutualSSLAuthenticatorServiceComponent.class);
             MockedStatic<CarbonAuthenticationUtil> authUtilMock =
                     Mockito.mockStatic(CarbonAuthenticationUtil.class);
             MockedStatic<MultitenantUtils> tenantUtilsMock =
                     Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<AuthenticatorsConfiguration> authConfigMock =
                     Mockito.mockStatic(AuthenticatorsConfiguration.class)) {

            // This is a sample comment for thumbprint mapping that doesn't include unauthorizeduser.
            java.util.Map<String, String> configParams = createThumbprintMappingConfig(
                    "CN=Test Issuer, O=Test Org, C=US", "96b24ad9d755125139cd790189a54f4ef2241b9b3cc44b5949fa8921527c62f5",
                    "admin,user2");
            setupMockAuthConfig(configParams, authConfigMock);
            setupStaticDependencies("unauthorizeduser", "carbon.super", serviceComponentMock, tenantUtilsMock);

            when(messageContext.getProperty(MessageContext.TRANSPORT_IN)).thenReturn(httpServletRequest);

            boolean result = mutualSSLAuthenticator.isAuthenticated(messageContext);
            assertFalse(result, "Authentication should fail for unauthorizeduser as it's not in the thumbprint mapping");
        }
    }

}
