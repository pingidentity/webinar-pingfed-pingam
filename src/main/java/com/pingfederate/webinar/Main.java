package com.pingfederate.webinar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.http.apache.ApacheHttpTransport;
import com.ping.demo.swagger.generated.v2.invoker.ApiClient;
import com.ping.demo.swagger.generated.v2.model.*;
import com.ping.demo.swagger.pf.PFSwaggerObjectMapper;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.logging.Logger;

public class Main {

    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());
    private Properties propsEnv;
    private ApiClient apiClient;
    private ApiHelper apiHelper;
    private String baseUrl;

    private JSONObject pingAmPdConfigTemplate;
    private String pingAmScriptNodeTemplate;

    public Main() {
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            propsEnv = new Properties();
            propsEnv.load(new FileInputStream(".env"));

            pingAmPdConfigTemplate = (JSONObject) new JSONParser().parse(new String(loader.getResourceAsStream("pingam-pd-config-template.json").readAllBytes()));
            pingAmScriptNodeTemplate = new String(loader.getResourceAsStream("pingam-script-node-template.js.txt").readAllBytes());
        } catch (Exception e) {
            LOGGER.severe(String.format("Required properties could not be loaded: %s. Exiting!", e.getMessage()));
            System.exit(0);
        }
    }

    public static void main(String[] args) {
        try {
            Main m = new Main();
            m.initializeApiClient();

            if (args.length > 0) {
                Set<String> arguments = new HashSet<>(Arrays.asList(args));
                if (arguments.contains("configure_pingfederate")) {
                    m.configurePingFederate();
                }
                if (arguments.contains("configure_pingam")) {
                    m.pingAmAuthenticateForSession();
                    m.configurePingAM();
                }
                if (arguments.contains("update_script_node")) {
                    m.pingAmAuthenticateForSession();
                    m.pingAmUpdateScriptNode();
                }
            } else {
                LOGGER.info("No argument was given. Provide configure_pingfederate or configure_pingam or both");
            }
        } catch (Exception e) {
            LOGGER.warning(e.getMessage());
        }
    }

    private void configurePingFederate() throws Exception {
        LOGGER.info("Configuring PingFederate now");

        // initialize PingFederate
        pfAcceptLicense();
        pfCreateAdminAccount();

        // configure PingFederate
        pfImportKeyAndCert();
        pfUpdateServerSettings();
        pfConfigureScopeManagement();
        String policyContractId = pfAddAuthenticationPolicyContract();
        pfAddAccessTokenManager();
        pfAddAccessTokenMapping(policyContractId);
        pfAddPolicyContractGrantMapping(policyContractId);
        pfAddOauthClient();
        pfAddOidcPolicyContract();
        pfAddTrackedHttpParameters();
        pfAddLdapDatastore();
        pfAddLdapPcv();
        pfAddHtmlFormAdapter();

        pfConfigurePingAmIntegrationKit("PingAMIdpAdapter", "PingAMIdpAdapterId", propsEnv.getProperty("PINGAM_JOURNEY"), null, null, false, false);
        pfAddIdpAdapterGrantMapping("PingAMIdpAdapterId");
        pfAddIdpAuthenticationPolicy("WebinarPingAMTree", "WebinarPingAMTreeId", policyContractId, "PingAMIdpAdapterId", "Delegates username, password authentication to PingAM", true);

        pfConfigurePingAmIntegrationKit("PingAMBackChannelAuthIdpAdapter", "PingAMBCAIdpAdapterId", propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_JOURNEY"), propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_ID"), propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_SECRET"), false, true);
        pfAddIdpAdapterGrantMapping("PingAMBCAIdpAdapterId");
        pfAddIdpAuthenticationPolicy("WebinarPingAMBCATree", "WebinarPingAMBCATreeId", policyContractId, "PingAMBCAIdpAdapterId", "Forwards a given login_hint to PingAM where that user provides his password", false);

        pfConfigurePingAmIntegrationKit("PingAMMfaOnlyIdpAdapter", "PingAMMfaOnlyIdpId", propsEnv.getProperty("PINGAM_MFA_JOURNEY"), propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_ID"), propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_SECRET"), true, false);
        pfAddIdpAdapterGrantMapping("PingAMMfaOnlyIdpId");
        pfAddMfaOnlyPolicy("WebinarMfaTree", policyContractId,"PingAMMfaOnlyIdpId", "WebinarMfaTreeId", "1. factor in PingFederate, 2. factor (OTP) in PingAM", false);

        LOGGER.info("PingFederate was configured successfully");
    }

    private void configurePingAM() throws Exception {
        LOGGER.info("Configuring PingAM now");

        // initialize PingAM
        pingAmCreateAdminAndConfig();
        pingAmAuthenticateForSession();
        // configure PingAM
        pingAmConfigureServerDefaults();
        pingAmConfigureGlobalServices();
        pingAmCreateRealm();
        pingAmConfigureRealm();
        pingAmConfigureDirectory();
        pingAmOAuth2ProviderService();
        pingAmBackChannelOAuthClient();
        pingAmAddForgeRockAuthenticatorPushService();
        pingAmAddForgeRockAuthenticatorOAthService();
        pingAmAddWebAuthNEncryptionService();
        pingAmAddSNSPushService();

        LOGGER.info("PingAM was configured successfully");
    }

    private void initializeApiClient() throws Exception {

        apiHelper = new ApiHelper(
                !"insecure".equalsIgnoreCase(propsEnv.getProperty("PINGAM_SSL_TRANSPORT")),
                !"insecure".equalsIgnoreCase(propsEnv.getProperty("PF_SSL_TRANSPORT")),
                propsEnv.getProperty("PINGAM_COOKIE"),
                propsEnv.getProperty("PF_ADMIN_USER"),
                propsEnv.getProperty("PF_ADMIN_PASSWORD"),
                propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")
        );

        baseUrl = String.format("https://%s/pf-admin-api/v1", propsEnv.getProperty("PF_ADMIN_NODE"));
        ApacheHttpTransport httpTransport = null;
        if ("insecure".equalsIgnoreCase(propsEnv.getProperty("PF_SSL_TRANSPORT"))) {
            ApacheHttpTransport.Builder builder = new ApacheHttpTransport.Builder();
            httpTransport = builder.doNotValidateCertificate().build();
        }
        apiClient = new ApiClient(
                baseUrl,
                httpTransport, httpRequest -> {
            httpRequest.getHeaders().put("X-XSRF-Header", "PingFederate");
            httpRequest.getHeaders().setBasicAuthentication(propsEnv.getProperty("PF_ADMIN_USER"), propsEnv.getProperty("PF_ADMIN_PASSWORD"));
        }, new PFSwaggerObjectMapper()
        );

    }

    private void pfCreateAdminAccount() throws IOException {

        AdministrativeAccount adminUser = null;
        try {
            adminUser = apiClient.administrativeAccountsApi().getAccount(propsEnv.getProperty("PF_ADMIN_USER"));
        } catch (Exception e) {
            if (e.getMessage().contains("401 Unauthorized")) {
                LOGGER.info("Going to add PingFederate admin account");
            } else {
                LOGGER.warning(String.format("PF admin account could not be created: %s. Exiting now", e.getMessage()));
                System.exit(0);
            }
        }
        if (adminUser == null) {

            AdministrativeAccount account = new AdministrativeAccount();
            account.setActive(true);
            account.setUsername(propsEnv.getProperty("PF_ADMIN_USER"));
            account.setPassword(propsEnv.getProperty("PF_ADMIN_PASSWORD"));
            account.setDescription("Admin Account created via Webinar setup");

            List<AdministrativeAccount.RolesEnum> roles = new ArrayList<>();
            roles.add(AdministrativeAccount.RolesEnum.ADMINISTRATOR);
            roles.add(AdministrativeAccount.RolesEnum.CRYPTO_ADMINISTRATOR);
            roles.add(AdministrativeAccount.RolesEnum.USER_ADMINISTRATOR);
            roles.add(AdministrativeAccount.RolesEnum.EXPRESSION_ADMINISTRATOR);
            roles.add(AdministrativeAccount.RolesEnum.DATA_COLLECTION_ADMINISTRATOR);
            account.setRoles(roles);

            apiClient.administrativeAccountsApi().addAccount(account);
        }
    }

    private void pingAmAuthenticateForSession() throws Exception {
        JSONObject authenticated = apiHelper.authenticatePingAm(
                propsEnv.getProperty("PINGAM_BASE_URL"),
                "/json/realms/root/authenticate",
                propsEnv.getProperty("PINGAM_ADMIN_USER"),
                propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")
        );

        if (authenticated.get("reason") != null) {
            LOGGER.severe("PingAM authentication failed, check the logs. Exiting");
            System.exit(0);
        }
    }

    private void pfAcceptLicense() throws IOException {
        LicenseAgreementInfo licenseAgreement = apiClient.licenseApi().getLicenseAgreement();
        if (!licenseAgreement.isAccepted()) {
            licenseAgreement = new LicenseAgreementInfo();
            licenseAgreement.setAccepted(true);
            apiClient.licenseApi().updateLicenseAgreement(licenseAgreement);
        }
    }

    private void pfImportKeyAndCert() throws Exception {

        InputStream keyStoreStream = new FileInputStream("dev/tlskey.p12");
        String keystore = Base64.getEncoder().encodeToString(keyStoreStream.readAllBytes());
        keyStoreStream.close();

        InputStream publicCertStream = new FileInputStream("dev/pubCert.crt");
        String publicCertString = Base64.getEncoder().encodeToString(publicCertStream.readAllBytes());
        publicCertStream.close();

        /* Import (if necessary) and active our key */
        boolean p12AlreadyImported = false;
        String p12Id = null;
        KeyPairViews keyPairs = apiClient.keyPairssslServerApi().getKeyPairs();
        for (KeyPairView next : keyPairs.getItems()) {
            if (String.format("CN=%s", propsEnv.getProperty("PINGAM_COOKIE_DOMAIN")).equalsIgnoreCase(next.getSubjectDN())) {
                p12AlreadyImported = true;
                p12Id = next.getId();
                break;
            }
        }
        if (!p12AlreadyImported) {
            KeyPairFile kpf = new KeyPairFile();
            kpf.setFormat(KeyPairFile.FormatEnum.PKCS12);
            kpf.setPassword(propsEnv.getProperty("SSL_PWD"));
            kpf.setFileData(keystore);
            p12Id = apiClient.keyPairssslServerApi().importKeyPair(kpf).getId();
        }

        SslServerSettings sslServerSettings = apiClient.keyPairssslServerApi().getSettings();

        List<ResourceLink> activeCerts = new ArrayList<>();
        ResourceLink link = createResourceLink(baseUrl, "/keyPairs/sslServer", p12Id);
        sslServerSettings.setRuntimeServerCertRef(link);
        sslServerSettings.setAdminConsoleCertRef(link);
        activeCerts.add(link);
        sslServerSettings.setActiveRuntimeServerCerts(activeCerts);
        sslServerSettings.setActiveAdminConsoleCerts(activeCerts);
        apiClient.keyPairssslServerApi().updateSettings(sslServerSettings);

        /* Import (if necessary) our public cert */
        boolean certAlreadyImported = false;
        CertViews trustedCAs = apiClient.certificatescaApi().getTrustedCAs();
        for (CertView next : trustedCAs.getItems()) {
            if (String.format("CN=%s", propsEnv.getProperty("PINGAM_COOKIE_DOMAIN")).equalsIgnoreCase(next.getSubjectDN())) {
                certAlreadyImported = true;
                break;
            }
        }
        if (!certAlreadyImported) {
            X509File x509File = new X509File();
            x509File.setFileData(publicCertString);
            apiClient.certificatescaApi().importTrustedCA(x509File);
        }
    }

    private void pfUpdateServerSettings() throws Exception {
        ServerSettings serverSettings = apiClient.serverSettingsApi().getServerSettings();
        FederationInfo federationInfo = serverSettings.getFederationInfo();
        federationInfo.setBaseUrl(propsEnv.getProperty("PF_FEDERATION_BASE_URL"));
        serverSettings.setFederationInfo(federationInfo);
        apiClient.serverSettingsApi().updateServerSettings(serverSettings);
    }

    private void pfConfigureScopeManagement() throws Exception {

        boolean hasOpenId = false, hasEmail = false, hasProfile = false;
        ScopeEntries commonScopes = apiClient.oauthauthServerSettingsApi().getCommonScopes(1, 25, null, null, true);
        for (ScopeEntry next : commonScopes.getItems()) {
            if ("openid".equals(next.getName())) {
                hasOpenId = true;
            } else if ("email".equals(next.getName())) {
                hasEmail = true;
            } else if ("profile".equals(next.getName())) {
                hasProfile = true;
            }
        }

        if (!hasOpenId) {
            ScopeEntry scopeOpenId = new ScopeEntry();
            scopeOpenId.setName("openid");
            scopeOpenId.setDescription("default openid connect scope");
            scopeOpenId.setDynamic(false);
            apiClient.oauthauthServerSettingsApi().addCommonScope(scopeOpenId);
        }
        if (!hasEmail) {
            ScopeEntry scopeEmail = new ScopeEntry();
            scopeEmail.setName("email");
            scopeEmail.setDescription("default email scope");
            scopeEmail.setDynamic(false);
            apiClient.oauthauthServerSettingsApi().addCommonScope(scopeEmail);
        }
        if (!hasProfile) {
            ScopeEntry scopeProfile = new ScopeEntry();
            scopeProfile.setName("profile");
            scopeProfile.setDescription("default profile scope");
            scopeProfile.setDynamic(false);
            apiClient.oauthauthServerSettingsApi().addCommonScope(scopeProfile);
        }

    }

    private String pfAddAuthenticationPolicyContract() throws Exception {

        AuthenticationPolicyContracts policyContracts = apiClient.authenticationPolicyContractsApi().getAuthenticationPolicyContracts(1, 20, null);
        for (AuthenticationPolicyContract next : policyContracts.getItems()) {
            if ("WebinarPolicyContract".equalsIgnoreCase(next.getName())) {
                return next.getId();
            }
        }

        AuthenticationPolicyContract contract = new AuthenticationPolicyContract();
        contract.setName("WebinarPolicyContract");

        AuthenticationPolicyContractAttribute contractAttribute = new AuthenticationPolicyContractAttribute();
        contractAttribute.setName("subject");

        contract.addCoreAttributesItem(contractAttribute);
        contract.setExtendedAttributes(new ArrayList<>());

        AuthenticationPolicyContract policyContract = apiClient.authenticationPolicyContractsApi().createAuthenticationPolicyContract(contract);
        return policyContract.getId();
    }

    private void pfAddAccessTokenManager() throws Exception {

        AccessTokenManagers tokenManagers = apiClient.oauthaccessTokenManagersApi().getTokenManagers();
        for (AccessTokenManager next : tokenManagers.getItems()) {
            if ("WebinarATM".equalsIgnoreCase(next.getId())) {
                return;
            }
        }

        AccessTokenManager atm = new AccessTokenManager();
        atm.setId("WebinarATM");
        atm.setName("WebinarATM");
        atm.setPluginDescriptorRef(
                createResourceLink(
                        baseUrl,
                        "/oauth/accessTokenManagers/descriptors",
                        "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin")
        );
        ConfigField fieldTokenUseCentralizedSigningKeys = new ConfigField();
        fieldTokenUseCentralizedSigningKeys.setName("Use Centralized Signing Key");
        fieldTokenUseCentralizedSigningKeys.setValue("true");
        fieldTokenUseCentralizedSigningKeys.setEncryptedValue(null);
        fieldTokenUseCentralizedSigningKeys.setInherited(false);

        ConfigField fieldJwsAlg = new ConfigField();
        fieldJwsAlg.setName("JWS Algorithm");
        fieldJwsAlg.setValue("RS256");
        fieldJwsAlg.setEncryptedValue(null);
        fieldJwsAlg.setInherited(false);

        PluginConfiguration pc = new PluginConfiguration();
        pc.addFieldsItem(fieldTokenUseCentralizedSigningKeys);
        pc.addFieldsItem(fieldJwsAlg);

        atm.setConfiguration(pc);

        AccessTokenAttribute attrUsername = new AccessTokenAttribute();
        attrUsername.setName("username");
        attrUsername.setMultiValued(false);

        AccessTokenAttributeContract atac = new AccessTokenAttributeContract();
        atac.addExtendedAttributesItem(attrUsername);
        atm.setAttributeContract(atac);

        TokenEndpointAttributeContract teac = new TokenEndpointAttributeContract();
        teac.setAttributes(new ArrayList<>());
        teac.setInherited(false);
        atm.setTokenEndpointAttributeContract(teac);

        atm.setSequenceNumber(5);

        apiClient.oauthaccessTokenManagersApi().createTokenManager(atm);

    }

    private void pfAddIdpAuthenticationPolicy(String policyTreeName, String policyTreeId, String authenticationPolicyContractId, String pingAmAdapterId, String description, boolean enabled) throws Exception {

        /* Fail branch */
        PolicyAction failAction = new PolicyAction();
        failAction.setType(PolicyAction.TypeEnum.DONE);
        failAction.setContext("Fail");

        AuthenticationPolicyTreeNode failNode = new AuthenticationPolicyTreeNode();
        failNode.setAction(failAction);

        /* Success branch */
        ApcMappingPolicyAction successAction = new ApcMappingPolicyAction();
        successAction.setType(PolicyAction.TypeEnum.APC_MAPPING);
        successAction.setContext("Success");
        successAction.setAuthenticationPolicyContractRef(
                createResourceLink(
                        baseUrl,
                        "/authenticationPolicyContracts",
                        authenticationPolicyContractId)
        );

        SourceTypeIdKey subjectSource = new SourceTypeIdKey();
        subjectSource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        subjectSource.setId(pingAmAdapterId);

        AttributeFulfillmentValue subject = new AttributeFulfillmentValue();
        subject.setSource(subjectSource);
        subject.setValue(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));

        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        fulfillmentValueMap.put("subject", subject);

        AttributeMapping mapping = new AttributeMapping();
        mapping.setAttributeContractFulfillment(fulfillmentValueMap);
        mapping.setAttributeSources(new ArrayList<>());
        successAction.setAttributeMapping(mapping);

        AuthenticationPolicyTreeNode successNode = new AuthenticationPolicyTreeNode();
        successNode.setAction(successAction);

        /* Source node */
        AuthnSourcePolicyAction rootAction = new AuthnSourcePolicyAction();
        rootAction.setType(PolicyAction.TypeEnum.AUTHN_SOURCE);
        AuthenticationSource authnSource = new AuthenticationSource();
        authnSource.setType(AuthenticationSource.TypeEnum.ADAPTER);
        authnSource.setSourceRef(createResourceLink(
                baseUrl,
                "/idp/adapters",
                pingAmAdapterId)
        );
        rootAction.setAuthenticationSource(authnSource);

        /* Root tree node */
        AuthenticationPolicyTreeNode rootNode = new AuthenticationPolicyTreeNode();
        rootNode.setAction(rootAction);
        rootNode.addChildrenItem(failNode);
        rootNode.addChildrenItem(successNode);

        AuthenticationPolicyTree tree = new AuthenticationPolicyTree();
        tree.setId(policyTreeId);
        tree.setName(policyTreeName);
        tree.setEnabled(enabled);
        tree.setDescription(description);
        tree.setHandleFailuresLocally(false);
        tree.setRootNode(rootNode);

        AuthenticationPolicy policy = new AuthenticationPolicy();
        policy.addAuthnSelectionTreesItem(tree);

        String policyString = new ObjectMapper().writeValueAsString(tree);
        policyString = policyString.replaceAll("\"type\":[\\\\s]{0,3}\"ApcMappingPolicyAction\",", "");
        policyString = policyString.replaceAll("\"type\":[\\\\s]{0,3}\"AuthnSourcePolicyAction\",", "");
        policyString = policyString.replaceAll("\"attributeRules\":[\\\\s]{0,3}null,", "");
        policyString = policyString.replaceAll("\"type\":[\\\\s]{0,3}\"PolicyAction\",", "");

        apiHelper.postPf(baseUrl, "/authenticationPolicies/policy", (JSONObject) new JSONParser().parse(policyString), new ArrayList<>());

        JSONObject payload = new JSONObject();
        payload.put("enableIdpAuthnSelection", true);
        payload.put("enableSpAuthnSelection", false);
        apiHelper.putPf(baseUrl, "/authenticationPolicies/settings", payload, new ArrayList<>());
    }

    private void pfAddOidcPolicyContract() throws Exception {

        OpenIdConnectPolicies connectPolicies = apiClient.oauthopenIdConnectApi().getPolicies();
        for (OpenIdConnectPolicy next : connectPolicies.getItems()) {
            if ("WebinarOidcPolicy".equalsIgnoreCase(next.getId())) {
                return;
            }
        }

        OpenIdConnectPolicy policy = new OpenIdConnectPolicy();
        policy.setId("WebinarOidcPolicy");
        policy.setName("WebinarOidcPolicy");
        policy.setAccessTokenManagerRef(
                createResourceLink(
                        baseUrl,
                        "/oauth/accessTokenManagers",
                        "WebinarATM")
        );
        policy.setIdTokenLifetime(5);

        OpenIdConnectAttribute attrUsername = new OpenIdConnectAttribute();
        attrUsername.setName("sub");
        attrUsername.setIncludeInIdToken(true);
        attrUsername.setIncludeInUserInfo(true);
        attrUsername.setMultiValued(false);

        OpenIdConnectAttributeContract oidcac = new OpenIdConnectAttributeContract();
        oidcac.addCoreAttributesItem(attrUsername);

        policy.setAttributeContract(oidcac);

        AttributeMapping mapping = new AttributeMapping();
        Map<String, AttributeFulfillmentValue> attributeFulfillmentValueMap = new HashMap();

        AttributeFulfillmentValue sub = new AttributeFulfillmentValue();

        SourceTypeIdKey subSource = new SourceTypeIdKey();
        subSource.setType(SourceTypeIdKey.TypeEnum.TOKEN);

        sub.setValue("username");
        sub.setSource(subSource);

        attributeFulfillmentValueMap.put("sub", sub);

        mapping.setAttributeContractFulfillment(attributeFulfillmentValueMap);
        mapping.setAttributeSources(new ArrayList<>());

        policy.setAttributeMapping(mapping);

        apiClient.oauthopenIdConnectApi().createPolicy(policy, false);
    }

    private void pfAddIdpAdapterGrantMapping(String pingAmAdapterId) throws Exception {

        IdpAdapterMapping mapping = new IdpAdapterMapping();
        mapping.setId(pingAmAdapterId);
        mapping.setIdpAdapterRef(createResourceLink(
                baseUrl,
                "/idp/adapters",
                pingAmAdapterId)
        );

        mapping.setAttributeSources(new ArrayList<>());

        SourceTypeIdKey userNameSource = new SourceTypeIdKey();
        userNameSource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);

        AttributeFulfillmentValue attrUserName = new AttributeFulfillmentValue();
        attrUserName.setSource(userNameSource);
        attrUserName.setValue(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));

        SourceTypeIdKey userKeySource = new SourceTypeIdKey();
        userKeySource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);

        AttributeFulfillmentValue attrUserKey = new AttributeFulfillmentValue();
        attrUserKey.setSource(userKeySource);
        attrUserKey.setValue(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));

        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        fulfillmentValueMap.put("USER_NAME", attrUserName);
        fulfillmentValueMap.put("USER_KEY", attrUserKey);

        mapping.setAttributeContractFulfillment(fulfillmentValueMap);

        apiClient.oauthidpAdapterMappingsApi().createIdpAdapterMapping(mapping, false);

    }

    private void pfAddPolicyContractGrantMapping(String authenticationPolicyContractId) throws Exception {

        ApcToPersistentGrantMappings grantMappings = apiClient.oauthauthenticationPolicyContractMappingsApi().getApcMappings();
        for (ApcToPersistentGrantMapping next : grantMappings.getItems()) {
            if (next.getAttributeContractFulfillment().get("USER_KEY") != null) {
                return;
            }
        }

        ApcToPersistentGrantMapping mapping = new ApcToPersistentGrantMapping();
        mapping.setAuthenticationPolicyContractRef(
                createResourceLink(
                        baseUrl,
                        "/authenticationPolicyContracts",
                        authenticationPolicyContractId)
        );

        SourceTypeIdKey userNameSource = new SourceTypeIdKey();
        userNameSource.setType(SourceTypeIdKey.TypeEnum.AUTHENTICATION_POLICY_CONTRACT);

        AttributeFulfillmentValue attrUserName = new AttributeFulfillmentValue();
        attrUserName.setSource(userNameSource);
        attrUserName.setValue("subject");

        SourceTypeIdKey userKeySource = new SourceTypeIdKey();
        userKeySource.setType(SourceTypeIdKey.TypeEnum.AUTHENTICATION_POLICY_CONTRACT);

        AttributeFulfillmentValue attrUserKey = new AttributeFulfillmentValue();
        attrUserKey.setSource(userKeySource);
        attrUserKey.setValue("subject");

        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        fulfillmentValueMap.put("USER_NAME", attrUserName);
        fulfillmentValueMap.put("USER_KEY", attrUserKey);

        mapping.setAttributeContractFulfillment(fulfillmentValueMap);
        mapping.setAttributeSources(new ArrayList<>());

        apiClient.oauthauthenticationPolicyContractMappingsApi().createApcMapping(mapping, false);

    }

    private void pfAddAccessTokenMapping(String authenticationPolicyContractId) throws Exception {

        List<AccessTokenMapping> tokenMappings = apiClient.oauthaccessTokenMappingsApi().getMappings();
        for (AccessTokenMapping next : tokenMappings) {
            if ("WebinarATM".equalsIgnoreCase(next.getAccessTokenManagerRef().getId())) {
                return;
            }
        }

        AccessTokenMapping mapping = new AccessTokenMapping();

        AccessTokenMappingContext ctxt = new AccessTokenMappingContext();
        ctxt.setType(AccessTokenMappingContext.TypeEnum.AUTHENTICATION_POLICY_CONTRACT);
        ctxt.setContextRef(
                createResourceLink(
                        baseUrl,
                        "/authenticationPolicyContracts",
                        authenticationPolicyContractId)
        );

        mapping.setContext(ctxt);
        mapping.setAccessTokenManagerRef(
                createResourceLink(
                        baseUrl,
                        "/oauth/accessTokenManagers",
                        "WebinarATM")
        );

        SourceTypeIdKey usernameSource = new SourceTypeIdKey();
        usernameSource.setType(SourceTypeIdKey.TypeEnum.AUTHENTICATION_POLICY_CONTRACT);

        AttributeFulfillmentValue attrUsername = new AttributeFulfillmentValue();
        attrUsername.setSource(usernameSource);
        attrUsername.setValue("subject");

        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        fulfillmentValueMap.put("username", attrUsername);

        mapping.setAttributeContractFulfillment(fulfillmentValueMap);
        mapping.setAttributeSources(new ArrayList<>());

        apiClient.oauthaccessTokenMappingsApi().createMapping(mapping, false);
    }

    private void pfAddOauthClient() throws Exception {

        String clientId = propsEnv.getProperty("PF_OAUTH_CLIENT_ID");
        if ((clientId != null) && !"".equalsIgnoreCase(clientId)) {

            Clients clients = apiClient.oauthclientsApi().getClients(1, 25, null);
            for (Client next : clients.getItems()) {
                if (clientId.equalsIgnoreCase(next.getClientId())) {
                    return;
                }
            }

            ClientAuth clientAuth = new ClientAuth();
            clientAuth.setType(ClientAuth.TypeEnum.SECRET);
            clientAuth.setSecret(propsEnv.getProperty("PF_OAUTH_CLIENT_SECRET"));

            Client client = new Client();
            client.setClientId(clientId);
            client.setClientAuth(clientAuth);
            client.addRedirectUrisItem(propsEnv.getProperty("PF_OAUTH_CLIENT_REDIRECT_URI"));
            client.setName(propsEnv.getProperty("PF_OAUTH_CLIENT_NAME"));
            client.setDescription("Client for Webinar");
            client.addRestrictedResponseTypesItem("code");
            client.addGrantTypesItem(Client.GrantTypesEnum.AUTHORIZATION_CODE);
            client.addGrantTypesItem(Client.GrantTypesEnum.REFRESH_TOKEN);
            client.setRestrictToDefaultAccessTokenManager(true);
            client.setDefaultAccessTokenManagerRef(
                    createResourceLink(
                            baseUrl,
                            "/oauth/accessTokenManagers",
                            "WebinarATM")
            );

            apiClient.oauthclientsApi().createClient(client);
        }
    }

    private void pfConfigurePingAmIntegrationKit(String adapterName, String adapterId, String journey, String clientId, String clientSecret, boolean includeSimpleParam, boolean includeAdvancedParam) throws IOException {

        /* Create PingAM IDP Adapter Configuration */

        IdpAdapter adapter = new IdpAdapter();
        adapter.setName(adapterName);
        adapter.setId(adapterId);
        adapter.setPluginDescriptorRef(
                createResourceLink(baseUrl,
                        "/idp/adapters/descriptors",
                        "com.pingidentity.adapters.pingam.PingAMAdapter"));

        PluginConfiguration pluginConfiguration = new PluginConfiguration();

        ConfigField fieldSimpleUsername = new ConfigField();
        fieldSimpleUsername.setName("Parameter Name");
        fieldSimpleUsername.setValue("username");

        ConfigField fieldSimpleSource = new ConfigField();
        fieldSimpleSource.setName("Source");
        fieldSimpleSource.setValue("com.pingidentity.adapter.input.parameter.userid.authenticated");

        ConfigRow configSimpleRowUsername = new ConfigRow();
        configSimpleRowUsername.addFieldsItem(fieldSimpleUsername);
        configSimpleRowUsername.addFieldsItem(fieldSimpleSource);
        configSimpleRowUsername.setDefaultRow(false);

        ConfigTable configTableSimpleParameter = new ConfigTable();
        configTableSimpleParameter.setName("Simple Parameter Mappings (optional)");
        configTableSimpleParameter.addRowsItem(configSimpleRowUsername);

        ConfigField fieldAdvancedUsername = new ConfigField();
        fieldAdvancedUsername.setName("Parameter Name");
        fieldAdvancedUsername.setValue("username");

        ConfigField fieldAdvancedSourceType = new ConfigField();
        fieldAdvancedSourceType.setName("Source Type");
        fieldAdvancedSourceType.setValue("com.pingidentity.adapter.tracked.http.request.params");

        ConfigField fieldAdvancedSourceParam = new ConfigField();
        fieldAdvancedSourceParam.setName("Source Parameter");
        fieldAdvancedSourceParam.setValue("login_hint");

        ConfigRow configAdvancedRowUsername = new ConfigRow();
        configAdvancedRowUsername.addFieldsItem(fieldAdvancedUsername);
        configAdvancedRowUsername.addFieldsItem(fieldAdvancedSourceType);
        configAdvancedRowUsername.addFieldsItem(fieldAdvancedSourceParam);
        configAdvancedRowUsername.setDefaultRow(false);

        ConfigTable configTableAdvancedParameter = new ConfigTable();
        configTableAdvancedParameter.setName("Advanced Parameter Mappings (optional)");
        configTableAdvancedParameter.addRowsItem(configAdvancedRowUsername);

        ConfigField fieldSessionIdLocal = new ConfigField();
        fieldSessionIdLocal.setName("Local Attribute");
        fieldSessionIdLocal.setValue("sessionId");

        ConfigField fieldSessionIdRemote = new ConfigField();
        fieldSessionIdRemote.setName("Journey Attribute Mapping");
        fieldSessionIdRemote.setValue("/sessionUid");

        ConfigRow configRowSession = new ConfigRow();
        configRowSession.addFieldsItem(fieldSessionIdLocal);
        configRowSession.addFieldsItem(fieldSessionIdRemote);
        configRowSession.setDefaultRow(false);

        ConfigField fieldRealmLocal = new ConfigField();
        fieldRealmLocal.setName("Local Attribute");
        fieldRealmLocal.setValue("realm");

        ConfigField fieldRealmRemote = new ConfigField();
        fieldRealmRemote.setName("Journey Attribute Mapping");
        fieldRealmRemote.setValue("/realm");

        ConfigRow configRowRealm = new ConfigRow();
        configRowRealm.addFieldsItem(fieldRealmLocal);
        configRowRealm.addFieldsItem(fieldRealmRemote);
        configRowRealm.setDefaultRow(false);

        ConfigTable configTable = new ConfigTable();
        configTable.setName("Journey Response Mappings (optional)");
        configTable.addRowsItem(configRowSession);
        configTable.addRowsItem(configRowRealm);

        if (includeSimpleParam) {
            pluginConfiguration.addTablesItem(configTableSimpleParameter);
        } else if (includeAdvancedParam) {
            pluginConfiguration.addTablesItem(configTableAdvancedParameter);
        }

        pluginConfiguration.addTablesItem(configTable);

        ConfigField pingAmBaseUrl = new ConfigField();
        pingAmBaseUrl.setName("Base URL");
        pingAmBaseUrl.setValue(propsEnv.getProperty("PINGAM_BASE_URL"));

        ConfigField pingAmRealm = new ConfigField();
        pingAmRealm.setName("Realm");
        pingAmRealm.setValue(propsEnv.getProperty("PINGAM_REALM"));

        ConfigField pingAmJourney = new ConfigField();
        pingAmJourney.setName("Journey");
        pingAmJourney.setValue(journey);

        ConfigField pingAmJourneyCookie = new ConfigField();
        pingAmJourneyCookie.setName("Cookie Name");
        pingAmJourneyCookie.setValue(propsEnv.getProperty("PINGAM_COOKIE"));

        pluginConfiguration.addFieldsItem(pingAmBaseUrl);
        pluginConfiguration.addFieldsItem(pingAmRealm);
        pluginConfiguration.addFieldsItem(pingAmJourney);
        pluginConfiguration.addFieldsItem(pingAmJourneyCookie);

        if (clientId != null) {
            ConfigField pingAmClientId = new ConfigField();
            pingAmClientId.setName("Client ID");
            pingAmClientId.setValue(clientId);
            pluginConfiguration.addFieldsItem(pingAmClientId);
            if (clientSecret != null) {
                ConfigField pingAmClientSecret = new ConfigField();
                pingAmClientSecret.setName("Client Secret");
                pingAmClientSecret.setValue(clientSecret);
                pluginConfiguration.addFieldsItem(pingAmClientSecret);
            }
        }

        adapter.setConfiguration(pluginConfiguration);

        IdpAdapterAttributeContract idpAdapterAttributeContract = new IdpAdapterAttributeContract();
        IdpAdapterAttribute attrUsername = new IdpAdapterAttribute();
        attrUsername.setName(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));
        attrUsername.setMasked(false);
        attrUsername.setPseudonym(true);
        idpAdapterAttributeContract.addCoreAttributesItem(attrUsername);
        idpAdapterAttributeContract.setMaskOgnlValues(false);

        adapter.setAttributeContract(idpAdapterAttributeContract);

        IdpAdapterContractMapping idpAdapterContractMapping = new IdpAdapterContractMapping();
        idpAdapterContractMapping.setAttributeSources(new ArrayList<>());
        Map<String, AttributeFulfillmentValue> stringAttributeFulfillmentValueMap = new HashMap<>();
        AttributeFulfillmentValue attrFulfilUsername = new AttributeFulfillmentValue();
        SourceTypeIdKey sourceFulfilUsername = new SourceTypeIdKey();
        sourceFulfilUsername.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        attrFulfilUsername.setSource(sourceFulfilUsername);
        attrFulfilUsername.setValue(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));
        stringAttributeFulfillmentValueMap.put(propsEnv.getProperty("PINGAM_USERNAME_ATTR"), attrFulfilUsername);
        idpAdapterContractMapping.setAttributeContractFulfillment(stringAttributeFulfillmentValueMap);

        adapter.setAttributeMapping(idpAdapterContractMapping);

        apiClient.idpadaptersApi().createIdpAdapter(adapter, true);

    }

    private void pfAddLdapDatastore() throws IOException {
        LdapDataStore ldap = new LdapDataStore();
        ldap.setType(DataStore.TypeEnum.LDAP);
        ldap.setId("WebinarLdapId");
        ldap.addHostnamesItem(String.format("%s:636", propsEnv.getProperty("HOSTNAME_PD")));
        ldap.setLdapType(LdapDataStore.LdapTypeEnum.PING_DIRECTORY);
        ldap.setUserDN("cn=administrator");
        ldap.setPassword("Password1");
        ldap.setUseSsl(true);
        ldap.setName("WebinarLdap");

        LdapTagConfig ldapTagConfig = new LdapTagConfig();
        ldapTagConfig.addHostnamesItem(String.format("%s:636", propsEnv.getProperty("HOSTNAME_PD")));
        ldapTagConfig.setDefaultSource(true);
        ldap.addHostnamesTagsItem(ldapTagConfig);

        apiClient.dataStoresApi().createDataStore(ldap, false);
    }

    private void pfAddLdapPcv() throws IOException {
        PasswordCredentialValidator pcv = new PasswordCredentialValidator();
        pcv.setId("WebinarLdapPCVId");
        pcv.setName("WebinarLdapPCV");
        pcv.setPluginDescriptorRef(
                createResourceLink(baseUrl,
                        "/idp/adapters/descriptors",
                        "org.sourceid.saml20.domain.LDAPUsernamePasswordCredentialValidator"));

        PluginConfiguration pluginConfiguration = new PluginConfiguration();
        pluginConfiguration.setTables(new ArrayList<>());

        ConfigField datastoreField = new ConfigField();
        datastoreField.setName("LDAP Datastore");
        datastoreField.setValue("WebinarLdapId");

        ConfigField searchBaseField = new ConfigField();
        searchBaseField.setName("Search Base");
        searchBaseField.setValue("dc=pingdirectory,dc=local");

        ConfigField searchFilterField = new ConfigField();
        searchFilterField.setName("Search Filter");
        searchFilterField.setValue("uid=${username}");

        pluginConfiguration.addFieldsItem(datastoreField);
        pluginConfiguration.addFieldsItem(searchBaseField);
        pluginConfiguration.addFieldsItem(searchFilterField);

        pcv.setConfiguration(pluginConfiguration);

        apiClient.passwordCredentialValidatorsApi().createPasswordCredentialValidator(pcv);
    }

    private void pfAddHtmlFormAdapter() throws IOException {

        IdpAdapter adapter = new IdpAdapter();
        adapter.setName("WebinarHtmlFormAdapter");
        adapter.setId("WebinarHtmlFormAdapterId");
        adapter.setPluginDescriptorRef(
                createResourceLink(baseUrl,
                        "/idp/adapters/descriptors",
                        "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"));

        PluginConfiguration pluginConfiguration = new PluginConfiguration();

        ConfigField pcv = new ConfigField();
        pcv.setName("Password Credential Validator Instance");
        pcv.setValue("WebinarLdapPCVId");

        ConfigRow configRowPcv = new ConfigRow();
        configRowPcv.addFieldsItem(pcv);
        configRowPcv.setDefaultRow(false);

        ConfigTable configTable = new ConfigTable();
        configTable.setName("Credential Validators");
        configTable.addRowsItem(configRowPcv);

        pluginConfiguration.addTablesItem(configTable);
        pluginConfiguration.setFields(new ArrayList<>());

        adapter.setConfiguration(pluginConfiguration);

        IdpAdapterAttributeContract idpAdapterAttributeContract = new IdpAdapterAttributeContract();

        IdpAdapterAttribute policyActionAttribute = new IdpAdapterAttribute();
        policyActionAttribute.setName("policy.action");
        policyActionAttribute.setMasked(false);
        policyActionAttribute.setPseudonym(false);

        IdpAdapterAttribute usernameAttribute = new IdpAdapterAttribute();
        usernameAttribute.setName("username");
        usernameAttribute.setMasked(false);
        usernameAttribute.setPseudonym(true);

        idpAdapterAttributeContract.addCoreAttributesItem(policyActionAttribute);
        idpAdapterAttributeContract.addCoreAttributesItem(usernameAttribute);

        idpAdapterAttributeContract.setUniqueUserKeyAttribute("username");
        adapter.setAttributeContract(idpAdapterAttributeContract);

        IdpAdapterContractMapping idpAdapterContractMapping = new IdpAdapterContractMapping();
        idpAdapterContractMapping.setAttributeSources(new ArrayList<>());
        Map<String, AttributeFulfillmentValue> stringAttributeFulfillmentValueMap = new HashMap<>();
        AttributeFulfillmentValue policyAction = new AttributeFulfillmentValue();
        SourceTypeIdKey policyActionSource = new SourceTypeIdKey();
        policyActionSource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        policyAction.setSource(policyActionSource);
        policyAction.setValue("policy.action");
        stringAttributeFulfillmentValueMap.put("policy.action", policyAction);

        AttributeFulfillmentValue username = new AttributeFulfillmentValue();
        SourceTypeIdKey usernameSource = new SourceTypeIdKey();
        usernameSource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        username.setSource(usernameSource);
        username.setValue("username");
        stringAttributeFulfillmentValueMap.put("username", username);
        idpAdapterContractMapping.setAttributeContractFulfillment(stringAttributeFulfillmentValueMap);
        adapter.setAttributeMapping(idpAdapterContractMapping);

        apiClient.idpadaptersApi().createIdpAdapter(adapter, true);

    }

    private void pfAddMfaOnlyPolicy(String policyTreeName, String authenticationPolicyContractId, String pingAmAdapterId, String policyTreeId, String description, boolean enabled) throws Exception {

        /* Fail branch */
        PolicyAction failAction = new PolicyAction();
        failAction.setType(PolicyAction.TypeEnum.DONE);
        failAction.setContext("Fail");

        AuthenticationPolicyTreeNode failNode = new AuthenticationPolicyTreeNode();
        failNode.setAction(failAction);

        /* PingAM node */
        AuthenticationPolicyTreeNode pingAmNode = new AuthenticationPolicyTreeNode();
        AuthnSourcePolicyAction pingAmNodeAction = new AuthnSourcePolicyAction();
        pingAmNodeAction.setType(PolicyAction.TypeEnum.AUTHN_SOURCE);
        pingAmNodeAction.setContext("Success");
        AuthenticationSource authenticationSource = new AuthenticationSource();
        authenticationSource.setType(AuthenticationSource.TypeEnum.ADAPTER);
        authenticationSource.setSourceRef(createResourceLink(
                baseUrl,
                "/idp/adapters",
                pingAmAdapterId)
        );
        pingAmNodeAction.setAuthenticationSource(authenticationSource);

        AttributeFulfillmentValue attributeFulfillmentValue = new AttributeFulfillmentValue();
        SourceTypeIdKey usernameSource = new SourceTypeIdKey();
        usernameSource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        usernameSource.setId("WebinarHtmlFormAdapterId");
        attributeFulfillmentValue.setSource(usernameSource);
        attributeFulfillmentValue.setValue("username");
        pingAmNodeAction.setInputUserIdMapping(attributeFulfillmentValue);
        pingAmNodeAction.setUserIdAuthenticated(true);

        pingAmNode.setAction(pingAmNodeAction);
        pingAmNode.addChildrenItem(failNode);

        /* APC mapping node */
        AuthenticationPolicyTreeNode apcMappingNode = new AuthenticationPolicyTreeNode();
        ApcMappingPolicyAction apcMappingAction = new ApcMappingPolicyAction();
        apcMappingAction.setType(PolicyAction.TypeEnum.APC_MAPPING);
        apcMappingAction.setContext("Success");
        apcMappingAction.setAuthenticationPolicyContractRef(
                createResourceLink(
                        baseUrl,
                        "/authenticationPolicyContracts",
                        authenticationPolicyContractId)
        );
        AttributeMapping subjectMapping = new AttributeMapping();
        subjectMapping.setAttributeSources(new ArrayList<>());
        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        AttributeFulfillmentValue subject = new AttributeFulfillmentValue();
        SourceTypeIdKey subjectSource = new SourceTypeIdKey();
        subjectSource.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        subjectSource.setId("WebinarHtmlFormAdapterId");
        subject.setSource(subjectSource);
        subject.setValue("username");
        fulfillmentValueMap.put("subject", subject);
        subjectMapping.setAttributeContractFulfillment(fulfillmentValueMap);
        subjectMapping.setIssuanceCriteria(new IssuanceCriteria());
        apcMappingAction.setAttributeMapping(subjectMapping);
        apcMappingNode.setAction(apcMappingAction);

        pingAmNode.addChildrenItem(apcMappingNode);

        /* Root node */
        AuthenticationPolicyTreeNode rootNode = new AuthenticationPolicyTreeNode();
        AuthnSourcePolicyAction htmlFormAdapterAction = new AuthnSourcePolicyAction();
        htmlFormAdapterAction.setType(PolicyAction.TypeEnum.AUTHN_SOURCE);
        AuthenticationSource htmlFormAdapterSource = new AuthenticationSource();
        htmlFormAdapterSource.setType(AuthenticationSource.TypeEnum.ADAPTER);
        htmlFormAdapterSource.setSourceRef(createResourceLink(
                baseUrl,
                "/idp/adapters",
                "WebinarHtmlFormAdapterId")
        );
        htmlFormAdapterAction.setAuthenticationSource(htmlFormAdapterSource);
        rootNode.setAction(htmlFormAdapterAction);
        rootNode.addChildrenItem(failNode);
        rootNode.addChildrenItem(pingAmNode);

        AuthenticationPolicyTree tree = new AuthenticationPolicyTree();
        tree.setId(policyTreeId);
        tree.setName(policyTreeName);
        tree.setDescription(description);
        tree.setEnabled(enabled);
        tree.setRootNode(rootNode);
        tree.setHandleFailuresLocally(false);

        AuthenticationPolicy policy = new AuthenticationPolicy();
        policy.addAuthnSelectionTreesItem(tree);

        String policyString = new ObjectMapper().writeValueAsString(tree);
        policyString = policyString.replaceAll("\"type\":[\\\\s]{0,3}\"ApcMappingPolicyAction\",", "");
        policyString = policyString.replaceAll("\"type\":[\\\\s]{0,3}\"AuthnSourcePolicyAction\",", "");
        policyString = policyString.replaceAll("\"attributeRules\":[\\\\s]{0,3}null,", "");
        policyString = policyString.replaceAll("\"type\":[\\\\s]{0,3}\"PolicyAction\",", "");

        apiHelper.postPf(baseUrl, "/authenticationPolicies/policy", (JSONObject) new JSONParser().parse(policyString), new ArrayList<>());
    }

    private void pfAddTrackedHttpParameters() throws Exception {
        String trackedParam = propsEnv.getProperty("PF_POLICY_TRACKED_PARAMETERS");
        if ((trackedParam != null) && !"".equalsIgnoreCase(trackedParam)) {
            List<Header> headers = new ArrayList<>();
            JSONObject resp = apiHelper.getPf(baseUrl, "/authenticationPolicies/default", headers);
            JSONArray tp = (JSONArray) resp.get("trackedHttpParameters");
            for (String next : trackedParam.split("[,; ]")) {
                tp.add(next);
            }
            apiHelper.putPf(baseUrl, "/authenticationPolicies/default", resp, headers);
        }
    }

// https://docs.pingidentity.com/pingam/8/eval-guide/step-3-deploy-am.html
// https://docs.pingidentity.com/pingam/7.5/reference/man-configurator-jar-1.html

    private void pingAmCreateAdminAndConfig() throws Exception {

        String basicPath = propsEnv.getProperty("PINGAM_BASE_URL");
        String path = "/config/configurator";

        List<BasicNameValuePair> payload = new ArrayList<>();
        payload.add(new BasicNameValuePair("SERVER_URL", propsEnv.getProperty("PINGAM_SERVER_URL")));
        payload.add(new BasicNameValuePair("DEPLOYMENT_URI", "openam"));
        payload.add(new BasicNameValuePair("BASE_DIR", "/root/openam")); // the location for logfiles within the docker container
        payload.add(new BasicNameValuePair("locale", "en_US"));
        payload.add(new BasicNameValuePair("PLATFORM_LOCALE", "en_US"));
        payload.add(new BasicNameValuePair("AM_ENC_KEY", propsEnv.getProperty("SSL_PWD")));
        payload.add(new BasicNameValuePair("ADMIN_PWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("ADMIN_CONFIRM_PWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("AMLDAPUSERPASSWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("COOKIE_DOMAIN", propsEnv.getProperty("PINGAM_COOKIE_DOMAIN")));
        payload.add(new BasicNameValuePair("acceptLicense", "true"));

        payload.add(new BasicNameValuePair("DATA_STORE", "dirServer"));
        payload.add(new BasicNameValuePair("DIRECTORY_SSL", "SSL"));
        payload.add(new BasicNameValuePair("DIRECTORY_SERVER", propsEnv.getProperty("HOSTNAME_DS")));
        payload.add(new BasicNameValuePair("DIRECTORY_PORT", "50636"));
        payload.add(new BasicNameValuePair("DIRECTORY_ADMIN_PORT", "4444"));
        payload.add(new BasicNameValuePair("DIRECTORY_JMX_PORT", "1689"));
        payload.add(new BasicNameValuePair("ROOT_SUFFIX", "ou=am-config")); // ou=am-config ou=identities
        payload.add(new BasicNameValuePair("DS_DIRMGRDN", "uid=am-config,ou=admins,ou=am-config"));
        payload.add(new BasicNameValuePair("DS_DIRMGRPASSWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));

        payload.add(new BasicNameValuePair("USERSTORE_TYPE", "LDAPv3ForOpenDS"));
        payload.add(new BasicNameValuePair("USERSTORE_SSL", "SSL"));
        payload.add(new BasicNameValuePair("USERSTORE_HOST", propsEnv.getProperty("HOSTNAME_DS")));
        payload.add(new BasicNameValuePair("USERSTORE_PORT", "50636"));
        payload.add(new BasicNameValuePair("USERSTORE_SUFFIX", "ou=identities"));
        payload.add(new BasicNameValuePair("USERSTORE_MGRDN", "uid=am-identity-bind-account,ou=admins,ou=identities"));
        payload.add(new BasicNameValuePair("USERSTORE_PASSWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));

        apiHelper.postPingAm(basicPath, path, payload, new ArrayList<>());
    }

    private void pingAmConfigureServerDefaults() throws Exception {

        String basicPath = String.format("%s/json/realms/root", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = "/global-config/servers/server-default/properties/security#1.0_update";

        List<Header> headers = new ArrayList<>();
        Header ifMatch = new BasicHeader("If-Match", "*");
        headers.add(ifMatch);

        JSONObject cookie = new JSONObject();
        cookie.put("com.iplanet.am.cookie.name", propsEnv.getProperty("PINGAM_COOKIE"));

        JSONObject payload = new JSONObject();
        payload.put("amconfig.header.cookie", cookie);

        apiHelper.putPingAm(basicPath, path, payload, headers);
    }

    private void pingAmConfigureGlobalServices() throws Exception {

        String basicPath = String.format("%s/json/realms/root", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = "/global-config/services/platform";

        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("If-Match", "*"));

        JSONArray cookieDomains = new JSONArray();
        cookieDomains.add(propsEnv.getProperty("PINGAM_COOKIE_DOMAIN"));

        JSONObject payload = new JSONObject();
        payload.put("cookieDomains", cookieDomains);

        // PUT https://openam.webinar.local:8449/openam/json/global-config/services/platform HTTP/1.1 --> 404, Not Found ???
        apiHelper.putPingAm(basicPath, path, payload, headers);
    }

    private void pingAmConfigureDirectory() throws Exception {

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = String.format("/realms/root/realms/%s/realm-config/services/id-repositories/LDAPv3/PingDirectory", propsEnv.getProperty("PINGAM_REALM"));

        updatePingAmPdTemplate();

        apiHelper.putPingAm(basicPath, path, pingAmPdConfigTemplate, new ArrayList<>());
    }

    private void pingAmBackChannelOAuthClient() throws Exception {

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = String.format("/realms/root/realms/%s/realm-config/agents/OAuth2Client/%s", propsEnv.getProperty("PINGAM_REALM"), propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_ID"));

        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Accept-API-Version", "resource=1.0"));

        JSONArray grantType = new JSONArray();
        grantType.add("client_credentials");
        JSONObject grantTypes = new JSONObject();
        grantTypes.put("inherited", false);
        grantTypes.put("value", grantType);

        JSONObject tokenEndpointAuthMethod = new JSONObject();
        tokenEndpointAuthMethod.put("inherited", false);
        tokenEndpointAuthMethod.put("value", "client_secret_basic");

        JSONObject advancedOAuth2ClientConfig = new JSONObject();
        advancedOAuth2ClientConfig.put("tokenEndpointAuthMethod", tokenEndpointAuthMethod);
        advancedOAuth2ClientConfig.put("grantTypes", grantTypes);

        JSONArray clientName = new JSONArray();
        clientName.add(propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_NAME"));
        JSONObject clientNames = new JSONObject();
        clientNames.put("inherited", false);
        clientNames.put("value", clientName);

        JSONObject clientType = new JSONObject();
        clientType.put("inherited", false);
        clientType.put("value", "confidential");

        JSONArray scope = new JSONArray();
        scope.add("back_channel_authentication");
        scope.add("write");
        JSONObject scopes = new JSONObject();
        scopes.put("inherited", false);
        scopes.put("value", scope);

        JSONObject coreOAuth2ClientConfig = new JSONObject();
        coreOAuth2ClientConfig.put("clientName", clientNames);
        coreOAuth2ClientConfig.put("clientType", clientType);
        coreOAuth2ClientConfig.put("userpassword", propsEnv.getProperty("PINGAM_BACK_CHANNEL_AUTH_CLIENT_SECRET"));
        coreOAuth2ClientConfig.put("scopes", scopes);

        JSONObject payload = new JSONObject();
        payload.put("advancedOAuth2ClientConfig", advancedOAuth2ClientConfig);
        payload.put("coreOAuth2ClientConfig", coreOAuth2ClientConfig);

        apiHelper.putPingAm(basicPath, path, payload, headers);
    }

    private void pingAmCreateRealm() throws Exception {
        // https://docs.pingidentity.com/pingam/8/setup-guide/sec-rest-realm-rest.html#rest-api-create-realm
        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = "/global-config/realms";

        // check if we have created it in the past already
        List<Header> headers = new ArrayList<>();
        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        // add the new realm
        JSONArray aliases = new JSONArray();
        aliases.add(pingAmRealm);
        JSONObject payload = new JSONObject();
        payload.put("name", pingAmRealm);
        payload.put("active", true);
        payload.put("parentPath", "/");
        payload.put("aliases", aliases);

        headers = new ArrayList<>();
        headers.add(new BasicHeader("Accept-API-Version", "resource=1.0"));
        apiHelper.postPingAm(basicPath, path, payload, headers);

        // use client-side sessions
        path = String.format("/realms/root/realms/%s/realm-config/authentication", pingAmRealm);
        payload = new JSONObject();
        payload.put("statelessSessionsEnabled", true);
        apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());

    }

    private void pingAmConfigureRealm() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        // User Attribute Mapping to Session Attribute
        String path = String.format("/realms/root/realms/%s/realm-config/authentication", pingAmRealm);

        JSONArray loginSuccessUrl = new JSONArray();
        loginSuccessUrl.add("/openam/console");
        JSONObject payload = new JSONObject();
        payload.put("loginSuccessUrl", loginSuccessUrl);
        payload.put("usernameGeneratorClass", "com.sun.identity.authentication.spi.DefaultUserIDGenerator");
        payload.put("usernameGeneratorEnabled", true);
        payload.put("loginPostProcessClass", new JSONArray());
        payload.put("loginFailureUrl", new JSONArray());

        JSONArray whitelist = new JSONArray(); // we need this further down
        whitelist.add("am.protected.sessionUsername");  // always available
        whitelist.add("am.protected.requestedJourney");  // always available

        JSONArray userAttributeSessionMapping = new JSONArray();
        userAttributeSessionMapping.add("cn|sessionUsername");  // always available

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if (ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for (String next : attributes) {
                // ["cn|sessionUsername","mail|email"]
                whitelist.add(String.format("am.protected.%s", next.trim()));
                userAttributeSessionMapping.add(String.format("%s|am.protected.%s", next.trim(), next.trim()));
            }
        }
        payload.put("userAttributeSessionMapping", userAttributeSessionMapping);

        apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());

        // use client-side sessions
        path = String.format("/realms/root/realms/%s/realm-config/authentication", pingAmRealm);
        payload = new JSONObject();
        payload.put("statelessSessionsEnabled", true);
        apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());

        // configure a validation service (redirect_uris) to the new realm
        path = String.format("/realms/root/realms/%s/realm-config/services/validation", pingAmRealm);
        JSONArray destinations = new JSONArray();
        destinations.add(String.format("%s/*", propsEnv.getProperty("PF_FEDERATION_BASE_URL")));
        destinations.add(String.format("%s/*?*", propsEnv.getProperty("PF_FEDERATION_BASE_URL")));
        payload = new JSONObject();
        payload.put("validGotoDestinations", destinations);
        apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());

        // configure session service lifetimes for the new realm
        path = String.format("/realms/root/realms/%s/realm-config/services/session", pingAmRealm);
        JSONObject attributes = new JSONObject();
        attributes.put("maxSessionTime", 2);
        attributes.put("maxIdleTime", 2);
        attributes.put("maxCachingTime", 3);
        attributes.put("quotaLimit", 1);
        payload = new JSONObject();
        payload.put("dynamic", attributes);
        apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());

        // add whitelisted session properties service for the new realm
        path = String.format("/realms/root/realms/%s/realm-config/services/amSessionPropertyWhitelist", pingAmRealm);
        payload = new JSONObject();
        payload.put("sessionPropertyWhitelist", whitelist);
        apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
    }

    private void pingAmOAuth2ProviderService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        // add oauth2 provider service to support back_channel_authentication
        String path = String.format("/realms/root/realms/%s/realm-config/services/oauth-oidc?_action=create", pingAmRealm);
        JSONArray supportedScopes = new JSONArray();
        supportedScopes.add("back_channel_authentication");
        supportedScopes.add("write");
        JSONObject advancedOAuth2Config = new JSONObject();
        advancedOAuth2Config.put("supportedScopes", supportedScopes);
        advancedOAuth2Config.put("persistentClaims", new JSONArray());
        advancedOAuth2Config.put("passwordGrantAuthService", "[Empty]");
        JSONObject advancedOIDCConfig = new JSONObject();
        advancedOIDCConfig.put("authorisedOpenIdConnectSSOClients", new JSONArray());
        JSONObject pluginsConfig = new JSONObject();
        pluginsConfig.put("oidcClaimsClass", "");
        pluginsConfig.put("accessTokenModifierClass", "");
        JSONObject payload = new JSONObject();
        payload.put("advancedOAuth2Config", advancedOAuth2Config);
        payload.put("advancedOIDCConfig", advancedOIDCConfig);
        payload.put("pluginsConfig", pluginsConfig);
        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Accept-API-Version", "resource=1.0"));
        apiHelper.postPingAm(basicPath, path, payload, headers);

        // add base url service
        path = String.format("/realms/root/realms/%s/realm-config/services/baseurl?_action=create", pingAmRealm);
        JSONObject _type = new JSONObject();
        advancedOAuth2Config.put("_id", "baseurl");
        advancedOAuth2Config.put("name", "Base URL Source");
        advancedOAuth2Config.put("collection", false);
        payload = new JSONObject();
        payload.put("source", "FIXED_VALUE");
        payload.put("fixedValue", propsEnv.getProperty("PINGAM_SERVER_URL"));
        payload.put("contextPath", "/openam");
        payload.put("_id", "");
        payload.put("_type", _type);
        apiHelper.postPingAm(basicPath, path, payload, headers);
    }

    private void pingAmAddForgeRockAuthenticatorPushService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        String path = String.format("/realms/root/realms/%s/realm-config/services/authenticatorPushService", pingAmRealm);

        JSONObject payload = new JSONObject();
        payload.put("authenticatorPushDeviceSettingsEncryptionKeystorePrivateKeyPassword", "changeit");
        payload.put("authenticatorPushDeviceSettingsEncryptionKeystorePassword", "changeit");
        payload.put("authenticatorPushDeviceSettingsEncryptionKeystoreKeyPairAlias", "WebinarPushKey");

        apiHelper.postPingAm(basicPath, path, payload, new ArrayList<>());
    }

    private void pingAmAddForgeRockAuthenticatorOAthService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        String path = String.format("/realms/root/realms/%s/realm-config/services/authenticatorOathService", pingAmRealm);

        JSONObject payload = new JSONObject();
        payload.put("authenticatorOATHDeviceSettingsEncryptionKeystorePrivateKeyPassword", "changeit");
        payload.put("authenticatorOATHDeviceSettingsEncryptionKeystorePassword", "changeit");
        apiHelper.postPingAm(basicPath, String.format("%s?_action=create", path), payload, new ArrayList<>());
    }

    private void pingAmAddSNSPushService() throws Exception {

        if (propsEnv.getProperty("SNS_ACCESS_KEY_ID") == null || "".equalsIgnoreCase(propsEnv.getProperty("SNS_ACCESS_KEY_ID"))) {
            LOGGER.info("Push service will not be configured since it has not been requested (no SNS_ACCESS_KEY_ID configured)");
        } else {
            String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

            String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

            String path = String.format("/realms/root/realms/%s/realm-config/services/pushNotification", pingAmRealm);

            JSONObject payload = new JSONObject();
            payload.put("accessKey", propsEnv.getProperty("SNS_ACCESS_KEY_ID"));
            payload.put("secret", propsEnv.getProperty("SNS_ACCESS_KEY_SECRET"));
            payload.put("googleEndpoint", propsEnv.getProperty("SNS_ENDPOINT_GCM"));
            payload.put("appleEndpoint", propsEnv.getProperty("SNS_ENDPOINT_APNS"));
            apiHelper.postPingAm(basicPath, String.format("%s?_action=create", path), payload, new ArrayList<>());
        }
    }

    private void pingAmAddWebAuthNEncryptionService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        String path = String.format("/realms/root/realms/%s/realm-config/services/authenticatorWebAuthnService", pingAmRealm);

        JSONObject payload = new JSONObject();
        payload.put("authenticatorWebAuthnDeviceSettingsEncryptionKeystorePassword", "changeit");
        payload.put("authenticatorWebAuthnDeviceSettingsEncryptionKeystorePrivateKeyPassword", "changeit");
        payload.put("authenticatorWebAuthnDeviceSettingsEncryptionKeystoreKeyPairAlias", "WebinarPushKey");
        apiHelper.postPingAm(basicPath, String.format("%s?_action=create", path), payload, new ArrayList<>());
    }

    private void updatePingAmPdTemplate() {
        pingAmPdConfigTemplate.replace("_id", "PingDirectory");
        JSONObject ldapsettings = (JSONObject) pingAmPdConfigTemplate.get("ldapsettings");
        ((JSONArray) ldapsettings.get("sun-idrepo-ldapv3-config-ldap-server")).add("pd.webinar.local:389");
        ldapsettings.replace("sun-idrepo-ldapv3-config-organization_name", "dc=pingdirectory,dc=local");
        ldapsettings.replace("sun-idrepo-ldapv3-config-authid", "cn=administrator");
        ldapsettings.replace("sun-idrepo-ldapv3-config-authpw", "Password1");

        JSONObject persistentsearch = (JSONObject) pingAmPdConfigTemplate.get("persistentsearch");
        persistentsearch.replace("sun-idrepo-ldapv3-config-psearchbase", "dc=pingdirectory,dc=local");
    }

    /**
     * Find the existing script assertion that extract user attributes from LDAP and update it to lookup the attributes defined in .env
     *
     * @throws Exception
     */
    private void pingAmUpdateScriptNode() throws Exception {
        String basicPath = String.format("%s/json/realms/root/realms/%s", propsEnv.getProperty("PINGAM_BASE_URL"), propsEnv.getProperty("PINGAM_REALM"));

        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Accept-APi-Version", "resource=1.1"));
        JSONObject scripts = apiHelper.getPingAm(basicPath, "/scripts?_queryFilter=true", headers);
        for (Object next : (JSONArray) scripts.get("result")) {
            if ("WebinarSetSessionProps".equalsIgnoreCase((String) ((JSONObject) next).get("name"))) {
                JSONObject script = (JSONObject) next;
                String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
                if (ldapAttributes != null) {
                    String attributes[] = ldapAttributes.split(",");
                    StringBuilder placeHolder1 = new StringBuilder();
                    StringBuilder placeHolder2 = new StringBuilder();
                    for (String nextAttr : attributes) {
                        placeHolder1.append(String.format("var %s = idRepository.getAttribute(userId, \"%s\").iterator().next();\n", nextAttr, nextAttr));
                        placeHolder2.append(String.format(".putSessionProperty(\"am.protected.%s\", %s)", nextAttr, nextAttr));
                    }
                    String updatedScript = pingAmScriptNodeTemplate.replaceAll("@@placeholder1@@", placeHolder1.toString());
                    updatedScript = updatedScript.replaceAll("@@placeholder2@@", placeHolder2.toString());
                    script.replace("script", Base64.getEncoder().encodeToString(updatedScript.getBytes()));

                    String scriptId = (String) script.get("_id");
                    headers.add(new BasicHeader("If-Match", "*"));

                    apiHelper.putPingAm(basicPath, String.format("/scripts/%s", scriptId), script, headers);

                    LOGGER.info("The script node was successfully updated");
                }
                break;
            }
        }
    }

    private ResourceLink createResourceLink(String baseUrl, String path, String id) {
        ResourceLink link = new ResourceLink();
        link.setId(id);
        link.setLocation(String.format("%s%s/%s", baseUrl, path, id));
        return link;
    }
}