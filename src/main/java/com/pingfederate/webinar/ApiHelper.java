package com.pingfederate.webinar;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.*;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

public class ApiHelper {

    private static final Logger LOGGER = Logger.getLogger(ApiHelper.class.getName());
    private final HttpClientBuilder pingAmApiBuilder;
    private final HttpClientBuilder pfApiBuilder;
    private String amTokenId;
    private final String sharedCookie;
    private final String pfUsername;
    private final String pfUserPassword;
    private final String pingAmPassword;

    public ApiHelper(boolean pingAmSecure, boolean pfSecure, String sharedCookie, String pfUsername, String pfUserPassword, String pingAmPassword) throws Exception {
        pingAmApiBuilder = HttpClientBuilder.create();
        pfApiBuilder = HttpClientBuilder.create();
        if (!pingAmSecure) {
            SSLContext sslCtx = getInsecureSslContext();
            pingAmApiBuilder.setSSLContext(sslCtx);
            pingAmApiBuilder.setSSLSocketFactory(getInsecureSslSocketFactory(sslCtx));
            pingAmApiBuilder.setSSLHostnameVerifier(getInsecureHostnameVerifier());
        }
        if (!pfSecure) {
            SSLContext sslCtx = getInsecureSslContext();
            pfApiBuilder.setSSLContext(sslCtx);
            pfApiBuilder.setSSLSocketFactory(getInsecureSslSocketFactory(sslCtx));
            pfApiBuilder.setSSLHostnameVerifier(getInsecureHostnameVerifier());
        }
        this.sharedCookie = sharedCookie;
        this.pfUsername = pfUsername;
        this.pfUserPassword = pfUserPassword;
        this.pingAmPassword = pingAmPassword;
    }

    public JSONObject postPf(String basePath, String path, JSONObject payload, List<Header> headers) throws Exception {
        return anyPf(payload, headers, new HttpPost(String.format("%s%s", basePath, path)));
    }

    public JSONObject putPf(String basePath, String path, JSONObject payload, List<Header> headers) throws Exception {
        return anyPf(payload, headers, new HttpPut(String.format("%s%s", basePath, path)));
    }

    private JSONObject anyPf(JSONObject payload, List<Header> headers, HttpEntityEnclosingRequestBase method) throws Exception {
        headers.add(new BasicHeader("Content-Type", "application/json"));
        headers.add(new BasicHeader("X-XSRF-Header", "PingFederate"));

        // When the initial PF admin account is created we have to exclude the Authorization header
        // However, the given username and password have to match the configured ones
        boolean includeAuthN = true;
        if ("POST".equalsIgnoreCase(method.getMethod())
                && method.getURI().toString().endsWith("/administrativeAccounts")
                && pfUsername.equalsIgnoreCase((String) payload.get("username"))
                && pfUserPassword.equals(payload.get("password"))
        ) {
            includeAuthN = false;
        }
        if (includeAuthN) {
            headers.add(new BasicHeader("Authorization", String.format("Basic %s", Base64.getEncoder().encodeToString(String.format("%s:%s", pfUsername, pfUserPassword).getBytes()))));
        }
        method.setEntity(new StringEntity(payload.toJSONString()));
        return any(headers, pfApiBuilder, method);
    }

    public JSONObject authenticatePingAm(String basePath, String path, String username, String password) {
        // https://backstage.forgerock.com/docs/am/7.4/authentication-guide/login-using-REST.html
        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("X-OpenAM-Username", username));
        headers.add(new BasicHeader("X-OpenAM-Password", password));
        headers.add(new BasicHeader("Content-Type", "application/json"));
        headers.add(new BasicHeader("Accept-API-Version", "resource=2.0, protocol=1.0"));
        JSONObject pingAm = any(headers, pingAmApiBuilder, new HttpPost(String.format("%s%s", basePath, path)));
        if (pingAm.get("tokenId") != null) {
            amTokenId = (String) pingAm.get("tokenId");
        }
        return pingAm;
    }

    public JSONObject getPingAm(String basePath, String path, List<Header> headers) {
        headers.add(new BasicHeader(sharedCookie, amTokenId));
        return any(headers, pingAmApiBuilder, new HttpGet(String.format("%s%s", basePath, path)));
    }

    public JSONObject postPingAm(String basePath, String path, JSONObject payload, List<Header> headers) throws Exception {
        return anyAm(payload, headers, new HttpPost(String.format("%s%s", basePath, path)));
    }

    public JSONObject postPingAm(String basePath, String path, List<BasicNameValuePair> payload, List<Header> headers) throws Exception {
        return anyAm(payload, headers, new HttpPost(String.format("%s%s", basePath, path)));
    }

    public JSONObject putPingAm(String basePath, String path, JSONObject payload, List<Header> headers) throws Exception {
        return anyAm(payload, headers, new HttpPut(String.format("%s%s", basePath, path)));
    }

    private JSONObject anyAm(JSONObject payload, List<Header> headers, HttpEntityEnclosingRequestBase httpMethod) throws Exception {
        if (payload != null) {
            httpMethod.setEntity(new StringEntity(payload.toJSONString()));
            headers.add(new BasicHeader("Content-Type", "application/json"));
        }
        headers.add(new BasicHeader(sharedCookie, amTokenId));
        return any(headers, pingAmApiBuilder, httpMethod);
    }

    private JSONObject anyAm(List<BasicNameValuePair> payload, List<Header> headers, HttpEntityEnclosingRequestBase httpMethod) throws Exception {
        boolean includeAuthN = true;
        if (payload != null) {
            httpMethod.setEntity(new UrlEncodedFormEntity(payload));
            headers.add(new BasicHeader("Content-Type", "application/x-www-form-urlencoded"));
            // When the initial PingAM admin account is created we have to exclude the session cookie
            // However, the given password has to match the configured one
            if ("POST".equalsIgnoreCase(httpMethod.getMethod()) && httpMethod.getURI().toString().endsWith("/config/configurator")) {
                for (BasicNameValuePair next : payload) {
                    // ADMIN_PWD indicates that this is the initial configuration flow
                    if ("ADMIN_PWD".equalsIgnoreCase(next.getName()) && pingAmPassword.equals(next.getValue())) {
                        includeAuthN = false;
                        break;
                    }
                }
            }
        }
        if (includeAuthN) {
            headers.add(new BasicHeader(sharedCookie, amTokenId));
        }
        return any(headers, pingAmApiBuilder, httpMethod);
    }

    private JSONObject any(List<Header> headers, HttpClientBuilder builder, HttpUriRequest httpMethod) {
        headers.add(new BasicHeader("Accept", "application/json"));
        for (Header next : headers) {
            httpMethod.setHeader(next);
        }

        HttpClient client = builder.build();

        JSONObject resp = new JSONObject();
        try {
            HttpResponse response = client.execute(httpMethod);
            String responseAsText = EntityUtils.toString(response.getEntity());
            if (response.getStatusLine().getStatusCode() >= 400) {
                LOGGER.warning(responseAsText);
            } else {
                LOGGER.info(responseAsText);
            }
            if (response.getHeaders("content-type").length == 0) {
                // no header 'Content-Type' indicates a response of type plain text
                resp.put("response_message", responseAsText);
            } else {
                resp = (JSONObject) new JSONParser().parse(responseAsText);
            }
        } catch (Exception e) {
            LOGGER.warning(e.getMessage());
        }
        return resp;
    }

    SSLContext getInsecureSslContext() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, new TrustManager[]
                {
                        new X509TrustManager() {

                            private X509Certificate[] accepted;

                            @Override
                            public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                            }

                            @Override
                            public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                                accepted = xcs;  // done on purpose to accept any self-signed certificates
                            }

                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return accepted;
                            }
                        }
                }, new java.security.SecureRandom());
        return sslCtx;
    }

    LayeredConnectionSocketFactory getInsecureSslSocketFactory(SSLContext sslCtx) {
        return new SSLConnectionSocketFactory(sslCtx);
    }

    HostnameVerifier getInsecureHostnameVerifier() {
        return (hostname, session) -> true;
    }
}
