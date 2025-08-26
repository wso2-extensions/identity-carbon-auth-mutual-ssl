/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.mutualssl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.axiom.om.util.Base64;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.services.authentication.CarbonServerAuthenticator;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.identity.authenticator.mutualssl.internal.MutualSSLAuthenticatorServiceComponent;
import org.wso2.carbon.user.api.TenantManager;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.AuthenticationObserver;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * Authenticator for certificate based two-way authentication
 */
public class MutualSSLAuthenticator implements CarbonServerAuthenticator {

    private static final int DEFAULT_PRIORITY_LEVEL = 5;
    private static final String AUTHENTICATOR_NAME = "MutualSSLAuthenticator";
    private static final String MUTUAL_SSL_URL = "http://mutualssl.carbon.wso2.org";

    /**
     * Header name of the username for mutual ssl authentication
     */
    private static final String USERNAME_HEADER = "UsernameHeader";

    /**
     * Configuration parameter name for trusted certificates list
     */
    private static final String WHITE_LIST = "WhiteList";

    /**
     * Configuration parameter name for enabling and disabling the trusted certificates list
     */
    private static final String WHITE_LIST_ENABLED = "WhiteListEnabled";

    private static final String THUMBPRINT_USER_MAPPING_PREFIX = "cert_thumbprint_";

    private static final String TRUSTED_ISSUER_LIST_CONFIG_NAME = "TrustedIssuers";
    private static final String TRUSTED_ISSUER_USER_MAPPING_PREFIX = "issuer_";
    private static final String ISSUER_SEPARATOR = "\\|";

    /**
     * Attribute name for reading client certificate in the request
     */
    private static final String JAVAX_SERVLET_REQUEST_CERTIFICATE = "javax.servlet.request.X509Certificate";

    /**
     * Character encoding for Base64 to String conversions
     */
    private static final String CHARACTER_ENCODING = "UTF-8";

    private static final String ENABLE_SHA256_CERTIFICATE_THUMBPRINT = "EnableSHA256";

    /**
     * Logger for the class
     */
    private static final Log log = LogFactory.getLog(MutualSSLAuthenticator.class);

    private static String usernameHeaderName = "UserName";
    private static String[] whiteList;
    private static boolean whiteListEnabled = false;
    private static boolean authenticatorInitialized = false;
    private static boolean enableSHA256CertificateThumbprint = true;
    private static final Map<String, Set<String>> thumbprintUserMapping = new HashMap<>();
    private static final Map<String, Set<String>> certIssuerToUserMapping = new HashMap<>();
    private static final Set<String> trustedIssuers = new HashSet<>();


    /**
     * Initialize Mutual SSL Authenticator Configuration
     */
    private synchronized static void init() {

        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();

        // Read configuration for mutual ssl authenticator
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);

        if (authenticatorConfig != null) {
            Map<String, String> configParameters = authenticatorConfig.getParameters();

            if (configParameters != null) {

                if (configParameters.containsKey(USERNAME_HEADER)) {
                    usernameHeaderName = configParameters.get(USERNAME_HEADER);
                }

                if (configParameters.containsKey(WHITE_LIST_ENABLED)) {
                    whiteListEnabled = Boolean.parseBoolean(configParameters.get(WHITE_LIST_ENABLED));

                    if (log.isDebugEnabled()) {
                        log.debug("Enabling trusted client certificates list : " + whiteListEnabled);
                    }
                }

                if (whiteListEnabled) {
                    // List of trusted thumbprints for clients is enabled
                    if (configParameters.containsKey(WHITE_LIST)) {
                        whiteList = configParameters.get(WHITE_LIST).trim().split(",");
                        int index = 0;
                        // Normalize thumbprints in the whitelist for consistent format.
                        for (String thumbprint : whiteList) {
                            String rawThumbprint = thumbprint.trim();
                            String normalizedThumbprint = normalizeThumbprint(rawThumbprint);
                            whiteList[index] = normalizedThumbprint;

                            if (log.isDebugEnabled()) {
                                log.debug("Client thumbprint added to whitelist - Original: '" + rawThumbprint + 
                                        "' -> Normalized: '" + normalizedThumbprint + "'");
                            }
                            index++;
                        }
                    } else {
                        log.error("Trusted client certificates list is enabled but empty");
                        return;
                    }
                }
                authenticatorInitialized = true;

                if (configParameters.containsKey(ENABLE_SHA256_CERTIFICATE_THUMBPRINT)) {
                    enableSHA256CertificateThumbprint = Boolean.parseBoolean(
                            configParameters.get(ENABLE_SHA256_CERTIFICATE_THUMBPRINT));
                }

                // Loading the trusted issuers.
                String issuerList = configParameters.get(TRUSTED_ISSUER_LIST_CONFIG_NAME);
                if (issuerList != null && !issuerList.trim().isEmpty()) {
                    String[] issuers = issuerList.split(ISSUER_SEPARATOR);
                    for (String issuer : issuers) {
                        String rawIssuer = issuer.trim();
                        if (!rawIssuer.isEmpty()) {
                            trustedIssuers.add(rawIssuer);
                        }
                    }
                }

                // Load certificate issuer to username mappings.
                for (Map.Entry<String, String> entry : configParameters.entrySet()) {
                    String configName = entry.getKey();
                    if (configName.startsWith(TRUSTED_ISSUER_USER_MAPPING_PREFIX)) {
                        String issuer = configName.substring(TRUSTED_ISSUER_USER_MAPPING_PREFIX.length());
                        if (trustedIssuers.contains(issuer)) {
                            String commaSeparatedUsernames = entry.getValue();
                            Set<String> usernames = getUsernames(commaSeparatedUsernames);
                            if (!usernames.isEmpty()) {
                                certIssuerToUserMapping.put(issuer, usernames);
                                if (log.isDebugEnabled()) {
                                    log.debug("Added certificate issuer to username mapping: " + issuer);
                                }
                            } else {
                                log.warn("No usernames configured for certificate issuer: " + issuer);
                            }
                        } else {
                            log.warn("Ignoring certificate issuer to username mapping for untrusted issuer: " +
                                    issuer);
                        }
                    } else if (configName.startsWith(THUMBPRINT_USER_MAPPING_PREFIX)) {
                        String thumbprint = configName.substring(THUMBPRINT_USER_MAPPING_PREFIX.length());
                        String normalizedThumbprint = normalizeThumbprint(thumbprint);
                        String commaSeparatedUsernames = entry.getValue();
                        Set<String> usernames = getUsernames(commaSeparatedUsernames);
                        if (!usernames.isEmpty()) {
                            thumbprintUserMapping.put(normalizedThumbprint, usernames);
                            if (log.isDebugEnabled()) {
                                log.debug("Added certificate thumbprint to username mapping: " + normalizedThumbprint);
                            }
                        } else {
                            log.warn("No usernames configured for certificate thumbprint: " + thumbprint);
                        }
                    }
                }
            }

        } else {
            if (log.isDebugEnabled()) {
                log.debug(AUTHENTICATOR_NAME + " configuration is not set for initialization");
            }
        }
    }

    private static Set<String> getUsernames(String commaSeparatedUsernames) {

        // Split comma-separated usernames and create a list.
        Set<String> usernames = new HashSet<>();
        if (!commaSeparatedUsernames.isEmpty()) {
            String[] usernameArray = commaSeparatedUsernames.split(",");
            for (String username : usernameArray) {
                String trimmedUsername = username.trim();
                if (!trimmedUsername.isEmpty()) {
                    usernames.add(trimmedUsername);
                }
            }
        }
        return usernames;
    }

    @Override
    public int getPriority() {

        AuthenticatorsConfiguration authenticatorsConfiguration =
                AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
        if (authenticatorConfig != null && authenticatorConfig.getPriority() > 0) {
            return authenticatorConfig.getPriority();
        }
        return DEFAULT_PRIORITY_LEVEL;
    }

    @Override
    public boolean isDisabled() {
        AuthenticatorsConfiguration authenticatorsConfiguration =
                AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            return authenticatorConfig.isDisabled();
        }
        return false;
    }

    @Override
    public boolean authenticateWithRememberMe(MessageContext msgCxt) {
        return false;
    }

    @Override
    public String getAuthenticatorName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public boolean isAuthenticated(MessageContext msgCxt) {
        boolean isAuthenticated = false;
        HttpServletRequest request = (HttpServletRequest) msgCxt.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
        Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
        try {
            if (certObject != null) {
                if (!authenticatorInitialized) {
                    init();
                }
                if (!authenticatorInitialized) {
                    log.error(AUTHENTICATOR_NAME + " failed initialization");
                    return false;
                }

                // <m:UserName xmlns:m="http://mutualssl.carbon.wso2.org"
                // soapenv:mustUnderstand="0">234</m:UserName>
                boolean trustedThumbprint = false;
                String thumbprint = null;
                X509Certificate[] cert = null;

                if (certObject instanceof X509Certificate[]) {
                    cert = (X509Certificate[]) certObject;

                    // Always get the thumbprint for validation
                    thumbprint = getThumbPrint(cert[0]);

                    if (log.isDebugEnabled()) {
                        log.debug("Client certificate thumbprint is " + thumbprint);
                    }

                    if (whiteListEnabled && whiteList != null) {
                        for (String whiteThumbprint : whiteList) {
                            if (thumbprint.equals(whiteThumbprint)) {
                                // Thumbprint of the client certificate is in the trusted list
                                trustedThumbprint = true;

                                if (log.isDebugEnabled()) {
                                    log.debug("Client certificate thumbprint matched with the white list");
                                }
                                break;
                            }
                        }
                    }
                }

                if (!whiteListEnabled || trustedThumbprint) {

                    // WhiteList is disabled or client certificate is in the trusted list
                    String userName = null;
                    String usernameInHeader = request.getHeader(usernameHeaderName);
                    boolean validHeader = false;

                    if (StringUtils.isNotEmpty(usernameInHeader)) {
                        //username is received in HTTP header encoded in base64
                        byte[] base64DecodedByteArray = Base64.decode(usernameInHeader);
                        userName = new String(base64DecodedByteArray, CHARACTER_ENCODING);
                        validHeader = true;

                        if (log.isDebugEnabled()) {
                            log.debug("Username for Mutual SSL : " + userName);
                        }
                    }

                    if (StringUtils.isEmpty(userName)) {
                        // Username is not received in HTTP Header. Check for SOAP header
                        SOAPEnvelope envelope = msgCxt.getEnvelope();
                        SOAPHeader header = envelope.getHeader();

                        if (header != null) {
                            List<SOAPHeaderBlock> headers = header.getHeaderBlocksWithNSURI(MUTUAL_SSL_URL);

                            if (headers != null) {
                                for (SOAPHeaderBlock soapHeaderBlock : headers) {
                                    if (usernameHeaderName.equals(soapHeaderBlock.getLocalName())) {
                                        // Username is received in SOAP header
                                        userName = soapHeaderBlock.getText();
                                        validHeader = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if (!validHeader && log.isDebugEnabled()) {
                        log.debug("'" + usernameHeaderName + "'" + " header is not received in HTTP or SOAP header");
                    }

                    if (StringUtils.isNotEmpty(userName)) {
                        String tenantDomain = MultitenantUtils.getTenantDomain(userName);
                        userName = MultitenantUtils.getTenantAwareUsername(userName);
                        TenantManager tenantManager =
                                MutualSSLAuthenticatorServiceComponent.getRealmService().getTenantManager();
                        int tenantId = tenantManager.getTenantId(tenantDomain);

                        handleAuthenticationStarted(tenantId);

                        UserStoreManager userstore =
                                MutualSSLAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId)
                                        .getUserStoreManager();

                        // Validate certificate to username binding if enabled.
                        if (validateCertificateUserBinding(cert, thumbprint, userName)) {
                            // If thumbprint to username mapping is valid or validation disabled, check user existence.
                            if (userstore.isExistingUser(userName)) {
                                // Username used for mutual ssl authentication is a valid user.
                                isAuthenticated = true;
                            }
                        }
                        if (isAuthenticated) {
                            CarbonAuthenticationUtil.onSuccessAdminLogin(request.getSession(), userName, tenantId,
                                    tenantDomain, "Mutual SSL Authentication");
                            handleAuthenticationCompleted(tenantId, true);
                            isAuthenticated = true;
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Authentication rquest is rejected. User " + userName +
                                        " does not exist in userstore");
                            }
                            CarbonAuthenticationUtil.onFailedAdminLogin(request.getSession(), userName, tenantId,
                                    "Mutual SSL Authentication", "User does not exist in userstore");
                            handleAuthenticationCompleted(tenantId, false);
                            isAuthenticated = false;
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Client Thumbprint " + thumbprint + " is not in the White List of " + AUTHENTICATOR_NAME);
                    }
                }

            } else {
                throw new IllegalStateException("The certificate cannot be empty");
            }
        } catch (Exception e) {
            log.error("Error authenticating the user " + e.getMessage(), e);
        }
        return isAuthenticated;
    }

    @Override
    public boolean isHandle(MessageContext msgCxt) {
        boolean canHandle = false;

        if (!isDisabled()) {

            if (!authenticatorInitialized) {
                init();
                if (!authenticatorInitialized) {
                    return canHandle;
                }
            }

            HttpServletRequest request = (HttpServletRequest) msgCxt.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
            String authorizationHeader = request.getHeader(HTTPConstants.HEADER_AUTHORIZATION);
            // This authenticator should kickin only if authorization headers are null
            if (authorizationHeader == null) {
                Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
                if (certObject != null) {
                    SOAPEnvelope envelope = msgCxt.getEnvelope();
                    SOAPHeader header = envelope.getHeader();
                    boolean validHeader = false;

                    if (header != null) {
                        List<SOAPHeaderBlock> headers = header.getHeaderBlocksWithNSURI(MUTUAL_SSL_URL);
                        if (headers != null) {
                            for (SOAPHeaderBlock soapHeaderBlock : headers) {
                                if (usernameHeaderName.equals(soapHeaderBlock.getLocalName())) {
                                    //Username can be in SOAP Header
                                    canHandle = true;
                                    validHeader = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!canHandle && StringUtils.isNotEmpty(request.getHeader(usernameHeaderName))) {
                        validHeader = true;
                        // Username is received in HTTP Header
                        canHandle = true;
                    }

                    if (!validHeader && log.isDebugEnabled()) {
                        log.debug("'" + usernameHeaderName + "'" + " header is not received in HTTP or SOAP header");
                    }

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Server is not picking up the client certificate. Mutual SSL authentication is not" +
                                "done");
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("MutualSSLAuthenticator is Disabled.");
            }
        }
        return canHandle;
    }

    /**
     * Helper method to retrieve the thumbprint of a X509 certificate
     *
     * @param cert X509 certificate
     * @return Thumbprint of the X509 certificate
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    private String getThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md;
        if (enableSHA256CertificateThumbprint) {
            md = MessageDigest.getInstance("SHA-256");
        } else {
            md = MessageDigest.getInstance("SHA-1");
        }
        byte[] certEncoded = cert.getEncoded();
        md.update(certEncoded);
        return hexify(md.digest());
    }

    /**
     * Helper method to hexify a byte array.
     *
     * @param bytes Bytes of message digest
     * @return Hexadecimal representation
     */
    private String hexify(byte bytes[]) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        for (byte byteValue : bytes) {
            builder.append(hexDigits[(byteValue & 0xf0) >> 4]).append(hexDigits[byteValue & 0x0f]);
        }
        return builder.toString();
    }

    /**
     * Helper method to normalize thumbprint format for consistent storage.
     * Converts both OpenSSL format (AB:CD:EF:...) and internal format (abcdef...) to internal format.
     * Supports wildcards (*) without modification.
     *
     * @param thumbprint Raw thumbprint string from configuration.
     * @return Normalized thumbprint in internal format (lowercase hex without separators)
     */
    private static String normalizeThumbprint(String thumbprint) {

        if (thumbprint == null || thumbprint.trim().isEmpty()) {
            return thumbprint;
        }

        String normalized = thumbprint.trim();

        // Handle wildcard - don't normalize.
        if ("*".equals(normalized)) {
            return normalized;
        }

        // Remove colons and convert to lowercase for internal format.
        normalized = normalized.replaceAll(":", "").toLowerCase();

        if (log.isDebugEnabled()) {
            if (!thumbprint.equals(normalized)) {
                log.debug("Normalized thumbprint from '" + thumbprint + "' to '" + normalized + "'");
            }
        }
        return normalized;
    }

    /**
     * Helper method to normalize and compare Distinguished Names (DNs) regardless of component ordering.
     * This method handles cases where DN components are in different orders but represent the same identity.
     * <p>
     * Examples:
     * - "C=SL, ST=Some-State, O=Internet Widgits Pty Ltd, CN=sahan"
     * - "CN=sahan, O=Internet Widgits Pty Ltd, ST=Some-State, C=SL"
     * <p>
     * Both DNs above will be considered equal.
     *
     * @param dn1 First Distinguished Name
     * @param dn2 Second Distinguished Name
     * @return true if DNs are equivalent, false otherwise
     */
    private static boolean isDNEqual(String dn1, String dn2) {

        if (dn1 == null && dn2 == null) {
            return true;
        }
        if (dn1 == null || dn2 == null) {
            return false;
        }

        // Quick check for exact string match.
        if (dn1.equals(dn2)) {
            return true;
        }

        // Normalize and compare DN components.
        String normalizedDN1 = normalizeDN(dn1);
        String normalizedDN2 = normalizeDN(dn2);

        return normalizedDN1.equals(normalizedDN2);
    }

    /**
     * Helper method to normalize a Distinguished Name by sorting its components.
     * This ensures that DNs with the same components in different orders are normalized to the same string.
     *
     * @param dn Distinguished Name to normalize
     * @return Normalized DN string with components sorted alphabetically
     */
    private static String normalizeDN(String dn) {

        if (dn == null || dn.trim().isEmpty()) {
            return dn;
        }

        try {
            // Split DN into components and normalize each.
            String[] components = dn.split(",");
            String[] normalizedComponents = new String[components.length];

            for (int i = 0; i < components.length; i++) {
                String component = components[i].trim();
                // Normalize whitespace around the equals sign.
                if (component.contains("=")) {
                    String[] parts = component.split("=", 2);
                    if (parts.length == 2) {
                        normalizedComponents[i] = parts[0].trim().toUpperCase() + "=" + parts[1].trim();
                    } else {
                        normalizedComponents[i] = component;
                    }
                } else {
                    normalizedComponents[i] = component;
                }
            }

            // Sort components to ensure consistent ordering.
            java.util.Arrays.sort(normalizedComponents);

            StringBuilder normalized = new StringBuilder();
            for (int i = 0; i < normalizedComponents.length; i++) {
                if (i > 0) {
                    normalized.append(", ");
                }
                normalized.append(normalizedComponents[i]);
            }

            String result = normalized.toString();

            if (log.isDebugEnabled()) {
                if (!dn.equals(result)) {
                    log.debug("Normalized DN from '" + dn + "' to '" + result + "'");
                }
            }

            return result;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to normalize DN: " + dn + ". Using original DN. Error: " + e.getMessage());
            }
            return dn; // Return original DN if normalization fails.
        }
    }

    /**
     * Helper method to validate certificate to username binding with issuer and thumbprint validation.
     * <p>
     * Validation flow:
     * 1. Check if certificate issuer is in trusted list
     * 2. If issuer mapping exists, validate username against issuer mapping
     * 3. If issuer validation passes, check thumbprint to username mapping with wildcard support
     * <p>
     * Supports the following patterns:
     * - specific thumbprint -> specific username(s)
     * - wildcard thumbprint (*) -> specific username(s)
     * - specific thumbprint -> wildcard username (*)
     * - wildcard thumbprint (*) -> wildcard username (*) [no validation]
     *
     * @param certificate X509 certificate array from client
     * @param thumbprint  Certificate thumbprint
     * @param userName    Username from header/SOAP
     * @return true if validation passes or is disabled, false if validation fails
     */
    private boolean validateCertificateUserBinding(X509Certificate[] certificate, String thumbprint, String userName) {

        if (certificate == null || certificate.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No certificate provided for validation");
            }
            return false;
        }

        // Step 1: Check if certificate issuer is in trusted list
        String issuerDN = certificate[0].getIssuerDN().getName();
        if (log.isDebugEnabled()) {
            log.debug("Certificate issuer DN: " + issuerDN);
        }

        if (!trustedIssuers.isEmpty()) {
            boolean issuerTrusted = false;
            for (String trustedIssuer : trustedIssuers) {
                if (isDNEqual(issuerDN, trustedIssuer)) {
                    issuerTrusted = true;
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate issuer matched trusted issuer: " + trustedIssuer);
                    }
                    break;
                }
            }

            if (!issuerTrusted) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate issuer is not in trusted list: " + issuerDN);
                }
                return false; // Certificate issuer is not trusted.
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Certificate issuer validation passed: " + issuerDN);
        }

        // Step 2: Check issuer to username mapping if configured.
        if (!certIssuerToUserMapping.isEmpty()) {
            Set<String> issuerExpectedUsernames = null;

            // Find matching issuer using DN comparison
            for (Map.Entry<String, Set<String>> entry : certIssuerToUserMapping.entrySet()) {
                if (isDNEqual(issuerDN, entry.getKey())) {
                    issuerExpectedUsernames = entry.getValue();
                    if (log.isDebugEnabled()) {
                        log.debug("Found issuer mapping for: " + entry.getKey());
                    }
                    break;
                }
            }

            if (issuerExpectedUsernames != null && !issuerExpectedUsernames.isEmpty()) {
                // Issuer mapping exists, validate username
                if (!issuerExpectedUsernames.contains("*") && !issuerExpectedUsernames.contains(userName)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate issuer to username binding validation failed. Issuer " + issuerDN);
                    }
                    return false; // Authentication failed due to issuer-username mismatch.
                }

                if (log.isDebugEnabled()) {
                    log.debug("Certificate issuer to username binding validation passed for issuer: " + issuerDN);
                }
            }
        }

        // Step 3: Check thumbprint to username mapping.
        if (thumbprint == null || thumbprintUserMapping.isEmpty()) {
            // If no thumbprint or no thumbprint mapping configured, skip thumbprint validation
            // but issuer validation already passed.
            return true;
        }

        // Check for wildcard thumbprint and wildcard username combination (no validation).
        Set<String> wildcardThumbprintUsers = thumbprintUserMapping.get("*");
        if (wildcardThumbprintUsers != null && wildcardThumbprintUsers.contains("*")) {
            if (log.isDebugEnabled()) {
                log.debug("Wildcard thumbprint (*) -> wildcard username (*) mapping found. No thumbprint" +
                        " validation performed.");
            }
            return true; // No thumbprint validation - accept any certificate with any username.
        }

        // First, try exact thumbprint match.
        Set<String> expectedUsernames = thumbprintUserMapping.get(thumbprint);

        // If no exact match, try wildcard thumbprint.
        if (expectedUsernames == null && wildcardThumbprintUsers != null) {
            expectedUsernames = wildcardThumbprintUsers;
            if (log.isDebugEnabled()) {
                log.debug("Using wildcard thumbprint (*) mapping for certificate: " + thumbprint);
            }
        }

        if (expectedUsernames == null || expectedUsernames.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No username mapping found for certificate thumbprint: " + thumbprint);
            }
            return false; // Authentication failed - no mapping for this certificate.
        }

        // Check if wildcard username is configured (accept any username for this thumbprint).
        if (expectedUsernames.contains("*")) {
            if (log.isDebugEnabled()) {
                log.debug("Wildcard username (*) configured for thumbprint: " + thumbprint);
            }
            return true;
        }

        // Check if the provided username is in the list of expected usernames.
        if (!expectedUsernames.contains(userName)) {
            if (log.isDebugEnabled()) {
                log.debug("Certificate to username binding validation failed. Certificate thumbprint " +
                        thumbprint + " is not mapped to the provided username: " + userName);
            }
            return false; // Authentication failed due to certificate-username mismatch.
        }

        if (log.isDebugEnabled()) {
            log.debug("Certificate to username binding validation passed for thumbprint: " + thumbprint);
        }
        return true;
    }

    private void handleAuthenticationStarted(int tenantId) {
        BundleContext bundleContext = MutualSSLAuthenticatorServiceComponent.getBundleContext();
        if (bundleContext != null) {
            ServiceTracker tracker =
                    new ServiceTracker(bundleContext,
                            AuthenticationObserver.class.getName(), null);
            tracker.open();
            Object[] services = tracker.getServices();
            if (services != null) {
                for (Object service : services) {
                    ((AuthenticationObserver) service).startedAuthentication(tenantId);
                }
            }
            tracker.close();
        }
    }

    private void handleAuthenticationCompleted(int tenantId, boolean isSuccessful) {
        BundleContext bundleContext = MutualSSLAuthenticatorServiceComponent.getBundleContext();
        if (bundleContext != null) {
            ServiceTracker tracker =
                    new ServiceTracker(bundleContext,
                            AuthenticationObserver.class.getName(), null);
            tracker.open();
            Object[] services = tracker.getServices();
            if (services != null) {
                for (Object service : services) {
                    ((AuthenticationObserver) service).completedAuthentication(
                            tenantId, isSuccessful);
                }
            }
            tracker.close();
        }
    }

}
