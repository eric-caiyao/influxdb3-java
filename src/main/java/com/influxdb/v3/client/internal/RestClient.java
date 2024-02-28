/*
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.influxdb.v3.client.internal;

import java.io.IOException;
import java.net.URISyntaxException;
//import java.net.http.HttpClient;
//import java.net.http.HttpRequest;
//import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.QueryStringEncoder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.influxdb.v3.client.InfluxDBApiException;
import com.influxdb.v3.client.config.ClientConfig;

final class RestClient implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(RestClient.class);

    private static final TrustManager[] TRUST_ALL_CERTS = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(
                        final java.security.cert.X509Certificate[] certs, final String authType) {
                }

                public void checkServerTrusted(
                        final java.security.cert.X509Certificate[] certs, final String authType) {
                }
            }
    };

    final String baseUrl;
    final String userAgent;
//    final HttpClient client;
    org.apache.http.client.HttpClient apacheClient;
    private final ClientConfig config;
    private Map<String, String> defaultHeaders;
    private final ObjectMapper objectMapper = new ObjectMapper();

    RestClient(@Nonnull final ClientConfig config) {
        Arguments.checkNotNull(config, "config");

        this.config = config;

        // user agent version
        Package mainPackage = RestClient.class.getPackage();
        String version = mainPackage != null ? mainPackage.getImplementationVersion() : "unknown";
        this.userAgent = String.format("influxdb3-java/%s", version != null ? version : "unknown");

        // URL
        String host = config.getHost();
        this.baseUrl = host.endsWith("/") ? host : String.format("%s/", host);

        HttpClientBuilder apacheClientBuild = HttpClientBuilder.create()
                .setDefaultRequestConfig(
                        RequestConfig.custom()
                                .setConnectTimeout((int) config.getTimeout().toMillis())
                                .setRedirectsEnabled(config.getAllowHttpRedirects())
                                // .setProxy(new HttpHost()config.getProxy().) proxy暂时用不到，先不适配
                                .build()
                );
        // timeout and redirects
//        HttpClient.Builder builder = HttpClient.newBuilder()
//                .connectTimeout(config.getTimeout())
//                .followRedirects(config.getAllowHttpRedirects()
//                        ? HttpClient.Redirect.NORMAL : HttpClient.Redirect.NEVER);

        // default headers
        if(config.getHeaders() != null){
            this.defaultHeaders = new HashMap<>(config.getHeaders());;
        }
//        this.defaultHeaders = config.getHeaders() != null ? Map.copyOf(config.getHeaders()) : null;

        // proxy  目前没有proxy场景，不需要使用
//        if (config.getProxy() != null) {
//            builder.proxy(config.getProxy());
//            if (config.getAuthenticator() != null) {
//                builder.authenticator(config.getAuthenticator());
//            }
//        }
        // 目前内部都是http请求，不需要使用
//        if (baseUrl.startsWith("https")) {
//            try {
//                if (config.getDisableServerCertificateValidation()) {
//                    SSLContext sslContext = SSLContext.getInstance("TLS");
//                    sslContext.init(null, TRUST_ALL_CERTS, new SecureRandom());
//                    builder.sslContext(sslContext);
//                }
//            } catch (Exception e) {
//                throw new RuntimeException(e);
//            }
//        }

//        this.client = builder.build();
        this.apacheClient = apacheClientBuild.build();
    }

    void request(@Nonnull final String path,
                 @Nonnull final HttpMethod method,
                 @Nullable final byte[] data,
                 @Nullable final Map<String, String> headers,
                 @Nullable final Map<String, String> queryParams) {

        if(HttpMethod.POST != method || data == null){
            // 目前只有使用post的场景，其他的暂时先不支持
            return;
        }
        QueryStringEncoder uriEncoder = new QueryStringEncoder(String.format("%s%s", baseUrl, path));
        if (queryParams != null) {
            queryParams.forEach((name, value) -> {
                if (value != null && !value.isEmpty()) {
                    uriEncoder.addParam(name, value);
                }
            });
        }
        HttpPost request = new HttpPost(uriEncoder.toString());
        if (defaultHeaders != null) {
            for (Map.Entry<String, String> entry : defaultHeaders.entrySet()) {
                request.addHeader(entry.getKey(), entry.getValue());
            }
        }
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                request.addHeader(entry.getKey(), entry.getValue());
            }
        }
        request.addHeader("User-Agent", userAgent);
        ByteArrayEntity entity = new ByteArrayEntity(data);
        request.setEntity(entity);
//        HttpRequest.Builder request = HttpRequest.newBuilder();
        // uri
//        try {
//            request.uri(uriEncoder.toUri());
//        } catch (URISyntaxException e) {
//            throw new InfluxDBApiException(e);
//        }

        // method and body
//        request.method(method.name(), data == null
//                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(data));

        // headers
//        if (defaultHeaders != null) {
//            for (Map.Entry<String, String> entry : defaultHeaders.entrySet()) {
//                request.header(entry.getKey(), entry.getValue());
//            }
//        }
//        if (headers != null) {
//            for (Map.Entry<String, String> entry : headers.entrySet()) {
//                request.header(entry.getKey(), entry.getValue());
//            }
//        }
//        request.header("User-Agent", userAgent);
        // 鉴权目前使用不到，先不支持
//        if (config.getToken() != null && config.getToken().length > 0) {
//            request.header("Authorization", String.format("Token %s", new String(config.getToken())));
//        }
        org.apache.http.HttpResponse response;
        try {
            LOG.error("start call: " + EntityUtils.toString(request.getEntity()));
            response = apacheClient.execute(request);
        } catch (IOException e) {
            LOG.error("call error: " + e.getMessage());
            throw new InfluxDBApiException(e);
        }
        int statusCode = response.getStatusLine().getStatusCode();
        LOG.error("status code: " + statusCode);
        if (statusCode < 200 || statusCode >= 300) {
//            String reason = "";
//            if (!body.isEmpty()) {
//                try {
//                    reason = objectMapper.readTree(body).get("message").asText();
//                } catch (JsonProcessingException e) {
//                    LOG.debug("Can't parse msg from response {}", response);
//                }
//            }

//            if (reason.isEmpty()) {
//                reason = Stream.of("X-Platform-Error-Code", "X-Influx-Error", "X-InfluxDb-Error")
//                        .map(response::getFirstHeader)
//                        .filter(message -> message != null).findFirst()
//                        .orElse(null);
//            }
//
//            if (reason.isEmpty()) {
//                reason = body;
//            }
//
//            if (reason.isEmpty()) {
//                reason = HttpResponseStatus.valueOf(statusCode).reasonPhrase();
//            }
//
//            String message = String.format("HTTP status code: %d; Message: %s", statusCode, reason);
//            throw new InfluxDBApiException();
        }

//        HttpResponse<String> response;
//        try {
//            response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
//        } catch (Exception e) {
//            throw new InfluxDBApiException(e);
//        }
//
//        int statusCode = response.statusCode();
//        if (statusCode < 200 || statusCode >= 300) {
//            String reason = "";
//            String body = response.body();
//            if (!body.isEmpty()) {
//                try {
//                    reason = objectMapper.readTree(body).get("message").asText();
//                } catch (JsonProcessingException e) {
//                    LOG.debug("Can't parse msg from response {}", response);
//                }
//            }
//
//            if (reason.isEmpty()) {
//                reason = Stream.of("X-Platform-Error-Code", "X-Influx-Error", "X-InfluxDb-Error")
//                        .map(name -> response.headers().firstValue(name).orElse(null))
//                        .filter(message -> message != null && !message.isEmpty()).findFirst()
//                        .orElse("");
//            }
//
//            if (reason.isEmpty()) {
//                reason = body;
//            }
//
//            if (reason.isEmpty()) {
//                reason = HttpResponseStatus.valueOf(statusCode).reasonPhrase();
//            }
//
//            String message = String.format("HTTP status code: %d; Message: %s", statusCode, reason);
//            throw new InfluxDBApiException(message);
//        }
    }

    @Override
    public void close() {
    }
}
