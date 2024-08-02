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

            if(args.length > 0) {
                Set<String> arguments = new HashSet<>(Arrays.asList(args));
                if(arguments.contains("update_script_node")) {
                    m.pingAmAuthenticateForSession();
                    m.pingAmUpdateScriptNode();
                    LOGGER.info("The script node was successfully updated");
                } else {
                    LOGGER.info("An unknown argument was given: %s");
                }
                System.exit(0);
            }

            LOGGER.info("Configuring PingFederate now");

            // initialize PingFederate
            m.pfAcceptLicense();
            m.pfCreateAdminAccount();

            // configure PingFederate
            m.pfImportKeyAndCert();
            m.pfUpdateServerSettings();
            m.pfConfigurePingAmIntegrationKit();
            m.pfConfigureScopeManagement();
            String policyContractId = m.pfAddAuthenticationPolicyContract();
            m.pfAddAccessTokenManager();
            m.pfAddAccessTokenMapping(policyContractId);
            m.pfAddPolicyContractGrantMapping(policyContractId);
            m.pfAddIdpAdapterGrantMapping();
            m.pfAddOidcPolicyContract();
            m.pfAddIdpAuthenticationPolicy(policyContractId);
            m.pfAddOauthClient();
            LOGGER.info("PingFederate was configured successfully");
            LOGGER.info("Configuring PingAM now");

            // initialize PingAM
            m.pingAmCreateAdminAndConfig();
            m.pingAmAuthenticateForSession();

            // configure PingAM
            m.pingAmConfigureServerDefaults();
            m.pingAmConfigureGlobalServices();
            m.pingAmCreateRealm();
            m.pingAmConfigureRealm();
            m.pingAmConfigureDirectory();
            m.pingAmAddForgeRockAuthenticatorPushService();
            m.pingAmAddForgeRockAuthenticatorOAthService();
            m.pingAmAddWebAuthNEncryptionService();
            m.pingAmAddSNSPushService();
            LOGGER.info("PingAM was configured successfully");

        } catch (Exception e) {
            LOGGER.warning(e.getMessage());
        }
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

            roles.add(AdministrativeAccount.RolesEnum.ADMINISTRATOR);
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

        AuthenticationPolicyContractAttribute sessionUsername = new AuthenticationPolicyContractAttribute();
        sessionUsername.setName("sessionUsername");
        AuthenticationPolicyContractAttribute requestedJourney = new AuthenticationPolicyContractAttribute();
        requestedJourney.setName("requestedJourney");
        contract.addExtendedAttributesItem(sessionUsername);
        contract.addExtendedAttributesItem(requestedJourney);

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                AuthenticationPolicyContractAttribute nextAttr = new AuthenticationPolicyContractAttribute();
                nextAttr.setName(next);
                contract.addExtendedAttributesItem(nextAttr);
            }
        }

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
        ConfigField fieldTokenUseCnetralizedSigningKeys = new ConfigField();
        fieldTokenUseCnetralizedSigningKeys.setName("Use Centralized Signing Key");
        fieldTokenUseCnetralizedSigningKeys.setValue("true");
        fieldTokenUseCnetralizedSigningKeys.setEncryptedValue(null);
        fieldTokenUseCnetralizedSigningKeys.setInherited(false);

        ConfigField fieldJwsAlg = new ConfigField();
        fieldJwsAlg.setName("JWS Algorithm");
        fieldJwsAlg.setValue("RS256");
        fieldJwsAlg.setEncryptedValue(null);
        fieldJwsAlg.setInherited(false);

        PluginConfiguration pc = new PluginConfiguration();
        pc.addFieldsItem(fieldTokenUseCnetralizedSigningKeys);
        pc.addFieldsItem(fieldJwsAlg);

        atm.setConfiguration(pc);

        AccessTokenAttribute attrUsername = new AccessTokenAttribute();
        attrUsername.setName("username");
        attrUsername.setMultiValued(false);

        AccessTokenAttribute attrSessionUsername = new AccessTokenAttribute();
        attrSessionUsername.setName("sessionUsername");
        attrSessionUsername.setMultiValued(false);

        AccessTokenAttribute attrRequestedJourney = new AccessTokenAttribute();
        attrRequestedJourney.setName("requestedJourney");
        attrRequestedJourney.setMultiValued(false);

        AccessTokenAttributeContract atac = new AccessTokenAttributeContract();
        atac.addExtendedAttributesItem(attrUsername);
        atac.addExtendedAttributesItem(attrSessionUsername);
        atac.addExtendedAttributesItem(attrRequestedJourney);

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                AccessTokenAttribute nextAttr = new AccessTokenAttribute();
                nextAttr.setName(next);
                nextAttr.setMultiValued(false);
                atac.addExtendedAttributesItem(nextAttr);
            }
        }

        atm.setAttributeContract(atac);

        atm.setSequenceNumber(5);

        apiClient.oauthaccessTokenManagersApi().createTokenManager(atm);

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

        SourceTypeIdKey source = new SourceTypeIdKey();
        source.setType(SourceTypeIdKey.TypeEnum.AUTHENTICATION_POLICY_CONTRACT);

        AttributeFulfillmentValue attrUsername = new AttributeFulfillmentValue();
        attrUsername.setSource(source);
        attrUsername.setValue("subject");

        AttributeFulfillmentValue attrSessionUsername = new AttributeFulfillmentValue();
        attrSessionUsername.setSource(source);
        attrSessionUsername.setValue("sessionUsername");

        AttributeFulfillmentValue attrRequestedJourney = new AttributeFulfillmentValue();
        attrRequestedJourney.setSource(source);
        attrRequestedJourney.setValue("requestedJourney");

        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        fulfillmentValueMap.put("username", attrUsername);
        fulfillmentValueMap.put("sessionUsername", attrSessionUsername);
        fulfillmentValueMap.put("requestedJourney", attrRequestedJourney);

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                AttributeFulfillmentValue nextAttr = new AttributeFulfillmentValue();
                nextAttr.setSource(source);
                nextAttr.setValue(next);
                fulfillmentValueMap.put(next, nextAttr);
            }
        }

        mapping.setAttributeContractFulfillment(fulfillmentValueMap);
        mapping.setAttributeSources(new ArrayList<>());

        apiClient.oauthaccessTokenMappingsApi().createMapping(mapping, false);
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

        OpenIdConnectAttribute attrSessionUsername = new OpenIdConnectAttribute();
        attrSessionUsername.setName("sessionUsername");
        attrSessionUsername.setIncludeInIdToken(false);
        attrSessionUsername.setIncludeInUserInfo(true);
        attrSessionUsername.setMultiValued(false);

        OpenIdConnectAttribute attrRequestedJourney = new OpenIdConnectAttribute();
        attrRequestedJourney.setName("requestedJourney");
        attrRequestedJourney.setIncludeInIdToken(false);
        attrRequestedJourney.setIncludeInUserInfo(true);
        attrRequestedJourney.setMultiValued(false);

        OpenIdConnectAttributeContract oidcac = new OpenIdConnectAttributeContract();
        oidcac.addCoreAttributesItem(attrUsername);
        oidcac.addExtendedAttributesItem(attrSessionUsername);
        oidcac.addExtendedAttributesItem(attrRequestedJourney);

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                OpenIdConnectAttribute nextAttr = new OpenIdConnectAttribute();
                nextAttr.setName(next);
                nextAttr.setIncludeInIdToken(false);
                nextAttr.setIncludeInUserInfo(true);
                nextAttr.setMultiValued(false);
                oidcac.addExtendedAttributesItem(nextAttr);
            }
        }

        policy.setAttributeContract(oidcac);

        Map<String, AttributeFulfillmentValue> attributeFulfillmentValueMap = new HashMap();

        SourceTypeIdKey source = new SourceTypeIdKey();
        source.setType(SourceTypeIdKey.TypeEnum.TOKEN);

        AttributeFulfillmentValue sub = new AttributeFulfillmentValue();
        sub.setValue("username");
        sub.setSource(source);
        attributeFulfillmentValueMap.put("sub", sub);

        AttributeFulfillmentValue sessionUsername = new AttributeFulfillmentValue();
        sessionUsername.setValue("sessionUsername");
        sessionUsername.setSource(source);
        attributeFulfillmentValueMap.put("sessionUsername", sessionUsername);

        AttributeFulfillmentValue requestedJourney = new AttributeFulfillmentValue();
        requestedJourney.setValue("requestedJourney");
        requestedJourney.setSource(source);
        attributeFulfillmentValueMap.put("requestedJourney", requestedJourney);

        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                AttributeFulfillmentValue nextValue = new AttributeFulfillmentValue();
                nextValue.setValue(next);
                nextValue.setSource(source);
                attributeFulfillmentValueMap.put(next, nextValue);
            }
        }

        AttributeMapping mapping = new AttributeMapping();
        mapping.setAttributeContractFulfillment(attributeFulfillmentValueMap);
        mapping.setAttributeSources(new ArrayList<>());

        policy.setAttributeMapping(mapping);

        Map<String, ParameterValues> scopesProfile = new HashMap<>();
        ParameterValues pv = new ParameterValues();
        pv.addValuesItem("sessionUsername");
        pv.addValuesItem("requestedJourney");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                pv.addValuesItem(next);
            }
        }
        scopesProfile.put("profile", pv);
        policy.setScopeAttributeMappings(scopesProfile);

        apiClient.oauthopenIdConnectApi().createPolicy(policy, false);
    }

    private void pfAddIdpAuthenticationPolicy(String authenticationPolicyContractId) throws Exception {

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

        SourceTypeIdKey source = new SourceTypeIdKey();
        source.setType(SourceTypeIdKey.TypeEnum.ADAPTER);
        source.setId("PingAMIdpAdapterId");

        AttributeFulfillmentValue subject = new AttributeFulfillmentValue();
        subject.setSource(source);
        subject.setValue(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));

        AttributeFulfillmentValue sessionUsername = new AttributeFulfillmentValue();
        sessionUsername.setSource(source);
        sessionUsername.setValue("sessionUsername");

        AttributeFulfillmentValue requestedJourney = new AttributeFulfillmentValue();
        requestedJourney.setSource(source);
        requestedJourney.setValue("requestedJourney");

        Map<String, AttributeFulfillmentValue> fulfillmentValueMap = new HashMap<>();
        fulfillmentValueMap.put("subject", subject);
        fulfillmentValueMap.put("sessionUsername", sessionUsername);
        fulfillmentValueMap.put("requestedJourney", requestedJourney);

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                AttributeFulfillmentValue nextValue = new AttributeFulfillmentValue();
                nextValue.setSource(source);
                nextValue.setValue(next);
                fulfillmentValueMap.put(next, nextValue);
            }
        }

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
                "PingAMIdpAdapterId")
        );
        rootAction.setAuthenticationSource(authnSource);

        /* Root tree node */
        AuthenticationPolicyTreeNode rootNode = new AuthenticationPolicyTreeNode();
        rootNode.setAction(rootAction);
        rootNode.addChildrenItem(failNode);
        rootNode.addChildrenItem(successNode);

        AuthenticationPolicyTree tree = new AuthenticationPolicyTree();
        tree.setId("WebinarPingAMTreeId");
        tree.setName("WebinarPingAMTree");
        tree.setEnabled(true);
        tree.setDescription("WebinarPolicy");
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

    private void pfAddIdpAdapterGrantMapping() throws Exception {

        IdpAdapterMappings idpAdapterMappings = apiClient.oauthidpAdapterMappingsApi().getIdpAdapterMappings();
        for (IdpAdapterMapping next : idpAdapterMappings.getItems()) {
            if ("PingAMIdpAdapterId".equalsIgnoreCase(next.getId())) {
                return;
            }
        }

        IdpAdapterMapping mapping = new IdpAdapterMapping();
        mapping.setId("PingAMIdpAdapterId");
        mapping.setIdpAdapterRef(createResourceLink(
                baseUrl,
                "/idp/adapters",
                "PingAMIdpAdapterId")
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

    private void pfConfigurePingAmIntegrationKit() throws IOException {

        IdpAdapters idpAdapters = apiClient.idpadaptersApi().getIdpAdapters(1, 20, null);
        for (IdpAdapter next : idpAdapters.getItems()) {
            if ("PingAMIdpAdapterId".equalsIgnoreCase(next.getId())) {
                return;
            }
        }

        IdpAdapter adapter = new IdpAdapter();
        adapter.setName("PingAMIdpAdapter");
        adapter.setId("PingAMIdpAdapterId");
        adapter.setPluginDescriptorRef(createResourceLink(baseUrl, "/idp/adapters/descriptors", "com.pingidentity.adapters.pingam.PingAMAdapter"));

        PluginConfiguration pluginConfiguration = new PluginConfiguration();

        ConfigTable configTable = new ConfigTable();
        configTable.setName("Journey Response Mappings (optional)");

        ConfigRow configRowSession = getPingAmAdapterMapping("sessionId", "/sessionUid");
        configTable.addRowsItem(configRowSession);

        ConfigRow configRowRealm = getPingAmAdapterMapping("realm", "/realm");
        configTable.addRowsItem(configRowRealm);

        ConfigRow configRowSessionUsername = getPingAmAdapterMapping("sessionUsername", "/properties/am.protected.sessionUsername");
        configTable.addRowsItem(configRowSessionUsername);

        ConfigRow configRowRequestedJourney = getPingAmAdapterMapping("requestedJourney", "/properties/am.protected.requestedJourney");
        configTable.addRowsItem(configRowRequestedJourney);

        String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                ConfigRow nextRow = getPingAmAdapterMapping(next, String.format("/properties/am.protected.%s", next));
                configTable.addRowsItem(nextRow);
            }
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
        pingAmJourney.setValue(propsEnv.getProperty("PINGAM_JOURNEY"));

        ConfigField pingAmJourneyCookie = new ConfigField();
        pingAmJourneyCookie.setName("Cookie Name");
        pingAmJourneyCookie.setValue(propsEnv.getProperty("PINGAM_COOKIE"));

        pluginConfiguration.addFieldsItem(pingAmBaseUrl);
        pluginConfiguration.addFieldsItem(pingAmRealm);
        pluginConfiguration.addFieldsItem(pingAmJourney);
        pluginConfiguration.addFieldsItem(pingAmJourneyCookie);

        adapter.setConfiguration(pluginConfiguration);

        IdpAdapterAttributeContract idpAdapterAttributeContract = new IdpAdapterAttributeContract();
        IdpAdapterAttribute attrUsername = new IdpAdapterAttribute();
        attrUsername.setName(propsEnv.getProperty("PINGAM_USERNAME_ATTR"));
        attrUsername.setMasked(false);
        attrUsername.setPseudonym(true);
        idpAdapterAttributeContract.addCoreAttributesItem(attrUsername);

        IdpAdapterAttribute attrSessionUsername = new IdpAdapterAttribute();
        attrSessionUsername.setName("sessionUsername");
        attrSessionUsername.setMasked(false);
        attrSessionUsername.setPseudonym(true);
        idpAdapterAttributeContract.addExtendedAttributesItem(attrSessionUsername);

        IdpAdapterAttribute attrRequestedJourney = new IdpAdapterAttribute();
        attrRequestedJourney.setName("requestedJourney");
        attrRequestedJourney.setMasked(false);
        attrRequestedJourney.setPseudonym(true);
        idpAdapterAttributeContract.addExtendedAttributesItem(attrRequestedJourney);

        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                IdpAdapterAttribute nextAttr = new IdpAdapterAttribute();
                nextAttr.setName(next);
                nextAttr.setMasked(false);
                nextAttr.setPseudonym(true);
                idpAdapterAttributeContract.addExtendedAttributesItem(nextAttr);
            }
        }

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

    private void pingAmCreateAdminAndConfig() throws Exception {

        String basicPath = propsEnv.getProperty("PINGAM_BASE_URL");
        String path = "/config/configurator";
        List<Header> headers = new ArrayList<>();

        List<BasicNameValuePair> payload = new ArrayList<>();
        payload.add(new BasicNameValuePair("ADMIN_PWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("ADMIN_CONFIRM_PWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("AMLDAPUSERPASSWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("AMLDAPUSERPASSWD_CONFIRM", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("BASE_DIR", "/forgerock/am_config"));
        payload.add(new BasicNameValuePair("DEPLOYMENT_URI", "openam"));
        payload.add(new BasicNameValuePair("DIRECTORY_JMX_PORT", "1689"));
        payload.add(new BasicNameValuePair("DS_DIRMGRDN", "cn=Directory Manager"));
        payload.add(new BasicNameValuePair("DS_DIRMGRPASSWD", propsEnv.getProperty("PINGAM_ADMIN_PASSWORD")));
        payload.add(new BasicNameValuePair("PLATFORM_LOCALE", "en_US"));
        payload.add(new BasicNameValuePair("SERVER_URL", basicPath.replaceAll("/openam$", "")));
        payload.add(new BasicNameValuePair("acceptLicense", "true"));
        payload.add(new BasicNameValuePair("locale", "en_US"));
        payload.add(new BasicNameValuePair("ROOT_SUFFIX", "dc=openam,dc=forgerock,dc=org"));
        payload.add(new BasicNameValuePair("COOKIE_DOMAIN", propsEnv.getProperty("PINGAM_COOKIE_DOMAIN")));
        payload.add(new BasicNameValuePair("DIRECTORY_SSL", "SSL"));
        payload.add(new BasicNameValuePair("DATA_STORE", "embedded"));
        payload.add(new BasicNameValuePair("DIRECTORY_PORT", "50636"));
        payload.add(new BasicNameValuePair("DIRECTORY_ADMIN_PORT", "4444"));
        payload.add(new BasicNameValuePair("DIRECTORY_SERVER", "localhost"));

        JSONObject posted = apiHelper.postPingAm(basicPath, path, payload, headers);
        LOGGER.info(posted.toJSONString());
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

        JSONObject posted = apiHelper.putPingAm(basicPath, path, payload, headers);
        LOGGER.info(posted.toJSONString());
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
        JSONObject posted = apiHelper.putPingAm(basicPath, path, payload, headers);
        LOGGER.info(posted.toJSONString());
    }

    private void pingAmConfigureDirectory() throws Exception {

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = String.format("/realms/root/realms/%s/realm-config/services/id-repositories/LDAPv3/PingDirectory", propsEnv.getProperty("PINGAM_REALM"));

        updatePingAmPdTemplate();

        JSONObject posted = apiHelper.putPingAm(basicPath, path, pingAmPdConfigTemplate, new ArrayList<>());
        LOGGER.info(posted.toJSONString());
    }

    private void pingAmCreateRealm() throws Exception {
        // https://backstage.forgerock.com/docs/am/7.4/setup-guide/sec-rest-realm-rest.html#rest-api-create-realm
        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));
        String path = "/global-config/realms";

        // check if we have created it in the past already
        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Accept-API-Version", "resource=1.0, protocol=2.1"));
        JSONObject existingRealms = apiHelper.getPingAm(basicPath, path + "?_queryFilter=true", headers);
        boolean isNew = true;
        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");
        for (Object next : (JSONArray) existingRealms.get("result")) {
            if (pingAmRealm.equalsIgnoreCase((String) ((JSONObject) next).get("name"))) {
                isNew = false;
                break;
            }
        }
        if (isNew) {

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
            JSONObject posted = apiHelper.postPingAm(basicPath, path, payload, headers);
            LOGGER.info(posted.toJSONString());

            // use client-side sessions
            path = String.format("/realms/root/realms/%s/realm-config/authentication", pingAmRealm);
            payload = new JSONObject();
            payload.put("statelessSessionsEnabled", true);
            JSONObject sessions = apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
            LOGGER.info(sessions.toJSONString());

        } else {
            LOGGER.info("The realm already exists and will not be created again");
        }

    }

    private void pingAmConfigureRealm() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        // User Attribute Mapping to Session Attribute
        String path = String.format("/realms/root/realms/%s/realm-config/authentication", pingAmRealm);

        JSONArray loginSuccessUrl = new JSONArray();
        loginSuccessUrl.add("/openam/console");
        JSONObject payload = new JSONObject();
        payload.put("loginSuccessUrl",loginSuccessUrl);
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
        if(ldapAttributes != null) {
            String attributes[] = ldapAttributes.split(",");
            for(String next : attributes) {
                // ["cn|sessionUsername","mail|email"]
                whitelist.add(String.format("am.protected.%s", next.trim()));
                userAttributeSessionMapping.add(String.format("%s|am.protected.%s", next.trim(), next.trim()));
            }
        }
        payload.put("userAttributeSessionMapping", userAttributeSessionMapping);

        JSONObject userAttributes = apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
        LOGGER.info(userAttributes.toJSONString());

        // use client-side sessions
        path = String.format("/realms/root/realms/%s/realm-config/authentication", pingAmRealm);
        payload = new JSONObject();
        payload.put("statelessSessionsEnabled", true);
        JSONObject sessions = apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
        LOGGER.info(sessions.toJSONString());

        // configure a validation service (redirect_uris) to the new realm
        path = String.format("/realms/root/realms/%s/realm-config/services/validation", pingAmRealm);
        JSONArray destinations = new JSONArray();
        destinations.add(String.format("%s/*", propsEnv.getProperty("PF_FEDERATION_BASE_URL")));
        destinations.add(String.format("%s/*?*", propsEnv.getProperty("PF_FEDERATION_BASE_URL")));
        payload = new JSONObject();
        payload.put("validGotoDestinations", destinations);
        JSONObject posted = apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
        LOGGER.info(posted.toJSONString());

        // configure session service lifetimes for the new realm
        path = String.format("/realms/root/realms/%s/realm-config/services/session", pingAmRealm);
        JSONObject attributes = new JSONObject();
        attributes.put("maxSessionTime", 2);
        attributes.put("maxIdleTime", 2);
        attributes.put("maxCachingTime", 3);
        attributes.put("quotaLimit", 1);
        payload = new JSONObject();
        payload.put("dynamic", attributes);
        posted = apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
        LOGGER.info(posted.toJSONString());

        // add whitelisted session properties service for the new realm
        path = String.format("/realms/root/realms/%s/realm-config/services/amSessionPropertyWhitelist", pingAmRealm);
        payload = new JSONObject();
        payload.put("sessionPropertyWhitelist", whitelist);
        posted = apiHelper.putPingAm(basicPath, path, payload, new ArrayList<>());
        LOGGER.info(posted.toJSONString());
    }

    private void pingAmAddForgeRockAuthenticatorPushService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        String path = String.format("/realms/root/realms/%s/realm-config/services/authenticatorPushService", pingAmRealm);

        JSONObject pushService = apiHelper.getPingAm(basicPath, path, new ArrayList<>());
        if (pushService.get("code") != null && 404 == (Long) pushService.get("code")) {
            JSONObject payload = new JSONObject();
            payload.put("authenticatorPushDeviceSettingsEncryptionKeystorePrivateKeyPassword", "changeit");
            payload.put("authenticatorPushDeviceSettingsEncryptionKeystorePassword", "changeit");
            payload.put("authenticatorPushDeviceSettingsEncryptionKeystoreKeyPairAlias", "WebinarPushKey");

            apiHelper.postPingAm(basicPath, path, payload, new ArrayList<>());
            LOGGER.info("Push service created");
        } else {
            LOGGER.info("Push service already exists");
        }
    }

    private void pingAmAddForgeRockAuthenticatorOAthService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        String path = String.format("/realms/root/realms/%s/realm-config/services/authenticatorOathService", pingAmRealm);

        JSONObject oauthServices = apiHelper.getPingAm(basicPath, path, new ArrayList<>());
        if (oauthServices.get("code") != null && 404 == (Long) oauthServices.get("code")) {
            JSONObject payload = new JSONObject();
            payload.put("authenticatorOATHDeviceSettingsEncryptionKeystorePrivateKeyPassword", "changeit");
            payload.put("authenticatorOATHDeviceSettingsEncryptionKeystorePassword", "changeit");
            apiHelper.postPingAm(basicPath, String.format("%s?_action=create", path), payload, new ArrayList<>());
            LOGGER.info("OAuth service created");
        } else {
            LOGGER.info("OAuth service already exists");
        }
    }

    private void pingAmAddSNSPushService() throws Exception {

        if (propsEnv.getProperty("SNS_ACCESS_KEY_ID") == null || "".equalsIgnoreCase(propsEnv.getProperty("SNS_ACCESS_KEY_ID"))) {
            LOGGER.info("Push service will not be configured since it has not been requested (no SNS_ACCESS_KEY_ID configured)");
        } else {
            String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

            String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

            String path = String.format("/realms/root/realms/%s/realm-config/services/pushNotification", pingAmRealm);

            JSONObject pushService = apiHelper.getPingAm(basicPath, path, new ArrayList<>());
            if (pushService.get("code") != null && 404 == (Long) pushService.get("code")) {
                JSONObject payload = new JSONObject();
                payload.put("accessKey", propsEnv.getProperty("SNS_ACCESS_KEY_ID"));
                payload.put("secret", propsEnv.getProperty("SNS_ACCESS_KEY_SECRET"));
                payload.put("googleEndpoint", propsEnv.getProperty("SNS_ENDPOINT_GCM"));
                payload.put("appleEndpoint", propsEnv.getProperty("SNS_ENDPOINT_APNS"));
                apiHelper.postPingAm(basicPath, String.format("%s?_action=create", path), payload, new ArrayList<>());
                LOGGER.info("Push service created");
            } else {
                LOGGER.info("Push service already exists");
            }
        }
    }

    private void pingAmAddWebAuthNEncryptionService() throws Exception {

        String pingAmRealm = propsEnv.getProperty("PINGAM_REALM");

        String basicPath = String.format("%s/json", propsEnv.getProperty("PINGAM_BASE_URL"));

        String path = String.format("/realms/root/realms/%s/realm-config/services/authenticatorWebAuthnService", pingAmRealm);

        JSONObject pushService = apiHelper.getPingAm(basicPath, path, new ArrayList<>());
        if (pushService.get("code") != null && 404 == (Long) pushService.get("code")) {
            JSONObject payload = new JSONObject();
            payload.put("authenticatorWebAuthnDeviceSettingsEncryptionKeystorePassword", "changeit");
            payload.put("authenticatorWebAuthnDeviceSettingsEncryptionKeystorePrivateKeyPassword", "changeit");
            payload.put("authenticatorWebAuthnDeviceSettingsEncryptionKeystoreKeyPairAlias", "WebinarPushKey");
            apiHelper.postPingAm(basicPath, String.format("%s?_action=create", path), payload, new ArrayList<>());
            LOGGER.info("WebAuthN service created");
        } else {
            LOGGER.info("WebAuthN service already exists");
        }
    }

    private void updatePingAmPdTemplate() {
        pingAmPdConfigTemplate.replace("_id", "PingDirectory");
        JSONObject ldapsettings = (JSONObject) pingAmPdConfigTemplate.get("ldapsettings");
        ((JSONArray) ldapsettings.get("sun-idrepo-ldapv3-config-ldap-server")).add("pd.webinar.local:389");
        ldapsettings.replace("sun-idrepo-ldapv3-config-organization_name", "dc=pingdirectory,dc=local");
        ldapsettings.replace("sun-idrepo-ldapv3-config-authid", "cn=administrator");
        ldapsettings.replace("sun-idrepo-ldapv3-config-authpw", "password");

        JSONObject persistentsearch = (JSONObject) pingAmPdConfigTemplate.get("persistentsearch");
        persistentsearch.replace("sun-idrepo-ldapv3-config-psearchbase", "dc=pingdirectory,dc=local");
    }

    /**
     * Find the existing script assertion that extract user attributes from LDAP and update it to lookup the attributes defined in .env
     * @throws Exception
     */
    private void pingAmUpdateScriptNode() throws Exception {
        String basicPath = String.format("%s/json/realms/root/realms/%s", propsEnv.getProperty("PINGAM_BASE_URL"), propsEnv.getProperty("PINGAM_REALM"));

        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Accept-APi-Version", "resource=1.1"));
        JSONObject scripts = apiHelper.getPingAm(basicPath, "/scripts?_queryFilter=true",headers);
        for(Object next : (JSONArray)scripts.get("result")) {
            if( "WebinarSetSessionProps".equalsIgnoreCase((String)((JSONObject)next).get("name"))) {
                JSONObject script = (JSONObject)next;
                String ldapAttributes = propsEnv.getProperty("PINGAM_LDAP_ATTRIBUTE");
                if(ldapAttributes != null) {
                    String attributes[] = ldapAttributes.split(",");
                    StringBuilder placeHolder1 = new StringBuilder();
                    StringBuilder placeHolder2 = new StringBuilder();
                    for(String nextAttr : attributes) {
                        placeHolder1.append(String.format("var %s = idRepository.getAttribute(userId, \"%s\").iterator().next();\n", nextAttr, nextAttr));
                        placeHolder2.append(String.format(".putSessionProperty(\"am.protected.%s\", %s)", nextAttr, nextAttr));
                    }
                    String updatedScript = pingAmScriptNodeTemplate.replaceAll("@@placeholder1@@", placeHolder1.toString());
                    updatedScript = updatedScript.replaceAll("@@placeholder2@@", placeHolder2.toString());
                    script.replace("script", Base64.getEncoder().encodeToString(updatedScript.getBytes()));

                    String scriptId = (String)script.get("_id");
                    headers.add(new BasicHeader("If-Match", "*"));

                    apiHelper.putPingAm(basicPath, String.format("/scripts/%s", scriptId), script, headers);
                }
                break;
            }
        }
    }

    private ConfigRow getPingAmAdapterMapping(String localValue, String remoteValue) {
        ConfigField localField = new ConfigField();
        localField.setName("Local Attribute");
        localField.setValue(localValue);
        ConfigField remoteField = new ConfigField();
        remoteField.setName("Journey Attribute Mapping");
        remoteField.setValue(remoteValue);
        ConfigRow row = new ConfigRow();
        row.addFieldsItem(localField);
        row.addFieldsItem(remoteField);
        row.setDefaultRow(false);
        return row;
    }

    private ResourceLink createResourceLink(String baseUrl, String path, String id) {
        ResourceLink link = new ResourceLink();
        link.setId(id);
        link.setLocation(String.format("%s%s/%s", baseUrl, path, id));
        return link;
    }
}