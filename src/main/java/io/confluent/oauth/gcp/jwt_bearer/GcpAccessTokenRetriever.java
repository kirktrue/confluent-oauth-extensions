package io.confluent.oauth.gcp.jwt_bearer;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.Retry;
import org.apache.kafka.common.security.oauthbearer.internals.secured.UnretryableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class GcpAccessTokenRetriever implements AccessTokenRetriever {
    private static final Logger logger = LoggerFactory.getLogger(GcpAccessTokenRetriever.class);

    private static final Set<Integer> UNRETRYABLE_HTTP_CODES;
    private static final int MAX_RESPONSE_BODY_LENGTH = 1000;

    static {
        // This does not have to be an exhaustive list. There are other HTTP codes that
        // are defined in different RFCs (e.g. https://datatracker.ietf.org/doc/html/rfc6585)
        // that we won't worry about yet. The worst case if a status code is missing from
        // this set is that the request will be retried.
        UNRETRYABLE_HTTP_CODES = new HashSet<>();
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_BAD_REQUEST);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_UNAUTHORIZED);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_PAYMENT_REQUIRED);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_FORBIDDEN);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_NOT_FOUND);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_BAD_METHOD);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_NOT_ACCEPTABLE);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_PROXY_AUTH);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_CONFLICT);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_GONE);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_LENGTH_REQUIRED);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_PRECON_FAILED);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_ENTITY_TOO_LARGE);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_REQ_TOO_LONG);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_UNSUPPORTED_TYPE);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_NOT_IMPLEMENTED);
        UNRETRYABLE_HTTP_CODES.add(HttpURLConnection.HTTP_VERSION);
    }

    private final String tokenSingingAlgo;
    private final String privateKeyId;
    private final String privateKeySecret;
    private final PrivateKey privateKey;
    private final String tokenSubject;
    private final String tokenIssuer;
    private final String tokenAudience;
    private final String tokenTargetAudience;
    private final SSLSocketFactory sslSocketFactory;
    private final String tokenEndpointUrl;
    private final long loginRetryBackoffMs;
    private final long loginRetryBackoffMaxMs;
    private final Integer loginConnectTimeoutMs;
    private final Integer loginReadTimeoutMs;

    public GcpAccessTokenRetriever(String tokenSigningAlgo,
                                          String privateKeyId,
                                          String privateKeySecret,
                                          String tokenSubject,
                                          String tokenIssuer,
                                          String tokenAudience,
                                          String tokenTargetAudience,
                                          SSLSocketFactory sslSocketFactory,
                                          String tokenEndpointUrl,
                                          long loginRetryBackoffMs,
                                          long loginRetryBackoffMaxMs,
                                          Integer loginConnectTimeoutMs,
                                          Integer loginReadTimeoutMs) {
        this.tokenSingingAlgo = Objects.requireNonNull(tokenSigningAlgo);
        this.privateKeyId = Objects.requireNonNull(privateKeyId);
        this.privateKeySecret = Objects.requireNonNull(privateKeySecret);
        this.tokenSubject = Objects.requireNonNull(tokenSubject);
        this.tokenIssuer = Objects.requireNonNull(tokenIssuer);
        this.tokenAudience = Objects.requireNonNull(tokenAudience);
        this.tokenTargetAudience = Objects.requireNonNull(tokenTargetAudience);
        this.sslSocketFactory = sslSocketFactory;
        this.tokenEndpointUrl = Objects.requireNonNull(tokenEndpointUrl);
        this.loginRetryBackoffMs = loginRetryBackoffMs;
        this.loginRetryBackoffMaxMs = loginRetryBackoffMaxMs;
        this.loginConnectTimeoutMs = loginConnectTimeoutMs;
        this.loginReadTimeoutMs = loginReadTimeoutMs;

        try {
            this.privateKey = getPrivateKeyFromSecret(this.privateKeySecret);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
            throw new ConfigException(String.format("Error getting private key from secret: %s", exception.getMessage()));
        }
    }

    /**
     * Retrieves a JWT access token in its serialized three-part form. The implementation
     * is free to determine how it should be retrieved but should not perform validation
     * on the result.
     *
     * <b>Note</b>: This is a blocking function and callers should be aware that the
     * implementation communicates over a network. The facility in the
     * {@link javax.security.auth.spi.LoginModule} from which this is ultimately called
     * does not provide an asynchronous approach.
     *
     * @return Non-<code>null</code> JWT access token string
     * @throws IOException Thrown on errors related to IO during retrieval
     */

    @Override
    public String retrieve() throws IOException {
        String requestBody = formatRequestBody();
        Retry<String> retry = new Retry<>(loginRetryBackoffMs, loginRetryBackoffMaxMs);
        Map<String, String> headers = Collections.singletonMap("Content-Type", "application/x-www-form-urlencoded");

        String responseBody;

        try {
            responseBody = retry.execute(() -> {
                HttpURLConnection con = null;

                try {
                    con = (HttpURLConnection) new URL(tokenEndpointUrl).openConnection();

                    if (sslSocketFactory != null && con instanceof HttpsURLConnection)
                        ((HttpsURLConnection) con).setSSLSocketFactory(sslSocketFactory);

                    return post(con, headers, requestBody, loginConnectTimeoutMs, loginReadTimeoutMs);
                } catch (IOException e) {
                    throw new ExecutionException(e);
                } finally {
                    if (con != null)
                        con.disconnect();
                }
            });
        } catch (ExecutionException e) {
            if (e.getCause() instanceof IOException)
                throw (IOException) e.getCause();
            else
                throw new KafkaException(e.getCause());
        }

        return parseAccessToken(responseBody);
    }

    public static String post(HttpURLConnection con,
                              Map<String, String> headers,
                              String requestBody,
                              Integer connectTimeoutMs,
                              Integer readTimeoutMs)
        throws IOException, UnretryableException {
        handleInput(con, headers, requestBody, connectTimeoutMs, readTimeoutMs);
        return handleOutput(con);
    }

    private static void handleInput(HttpURLConnection con,
                                    Map<String, String> headers,
                                    String requestBody,
                                    Integer connectTimeoutMs,
                                    Integer readTimeoutMs)
        throws IOException, UnretryableException {
        logger.debug("handleInput - starting post for {}", con.getURL());
        con.setRequestMethod("POST");
        con.setRequestProperty("Accept", "application/json");

        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet())
                con.setRequestProperty(header.getKey(), header.getValue());
        }

        con.setRequestProperty("Cache-Control", "no-cache");

        if (requestBody != null) {
            con.setRequestProperty("Content-Length", String.valueOf(requestBody.length()));
            con.setDoOutput(true);
        }

        con.setUseCaches(false);

        if (connectTimeoutMs != null)
            con.setConnectTimeout(connectTimeoutMs);

        if (readTimeoutMs != null)
            con.setReadTimeout(readTimeoutMs);

        logger.debug("handleInput - preparing to connect to {}", con.getURL());
        con.connect();

        if (requestBody != null) {
            try (OutputStream os = con.getOutputStream()) {
                ByteArrayInputStream is = new ByteArrayInputStream(requestBody.getBytes(StandardCharsets.UTF_8));
                logger.debug("handleInput - preparing to write request body to {}", con.getURL());
                copy(is, os);
            }
        }
    }

    static String handleOutput(final HttpURLConnection con) throws IOException {
        int responseCode = con.getResponseCode();
        logger.debug("handleOutput - responseCode: {}", responseCode);

        // NOTE: the contents of the response should not be logged so that we don't leak any
        // sensitive data.
        String responseBody = null;

        // NOTE: It is OK to log the error response body and/or its formatted version as
        // per the OAuth spec, it doesn't include sensitive information.
        // See https://www.ietf.org/rfc/rfc6749.txt, section 5.2
        String errorResponseBody = null;

        try (InputStream is = con.getInputStream()) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            logger.debug("handleOutput - preparing to read response body from {}", con.getURL());
            copy(is, os);
            responseBody = os.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            // there still can be useful error response from the servers, lets get it
            try (InputStream is = con.getErrorStream()) {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                logger.debug("handleOutput - preparing to read error response body from {}", con.getURL());
                copy(is, os);
                errorResponseBody = os.toString(StandardCharsets.UTF_8);
            } catch (Exception e2) {
                logger.warn("handleOutput - error retrieving error information", e2);
            }
            logger.warn("handleOutput - error retrieving data", e);
        }

        if (responseCode == HttpURLConnection.HTTP_OK || responseCode == HttpURLConnection.HTTP_CREATED) {
            logger.debug("handleOutput - responseCode: {}, error response: {}", responseCode,
                errorResponseBody);

            if (responseBody == null || responseBody.isEmpty())
                throw new IOException(String.format("The token endpoint response was unexpectedly empty despite response code %d from %s and error message %s",
                    responseCode, con.getURL(), formatErrorMessage(errorResponseBody)));

            return responseBody;
        } else {
            logger.warn("handleOutput - error response code: {}, error response body: {}", responseCode,
                formatErrorMessage(errorResponseBody));

            if (UNRETRYABLE_HTTP_CODES.contains(responseCode)) {
                // We know that this is a non-transient error, so let's not keep retrying the
                // request unnecessarily.
                throw new UnretryableException(new IOException(String.format("The response code %s and error response %s was encountered reading the token endpoint response; will not attempt further retries",
                    responseCode, formatErrorMessage(errorResponseBody))));
            } else {
                // We don't know if this is a transient (retryable) error or not, so let's assume
                // it is.
                throw new IOException(String.format("The unexpected response code %s and error message %s was encountered reading the token endpoint response",
                    responseCode, formatErrorMessage(errorResponseBody)));
            }
        }
    }

    static void copy(InputStream is, OutputStream os) throws IOException {
        byte[] buf = new byte[4096];
        int b;

        while ((b = is.read(buf)) != -1)
            os.write(buf, 0, b);
    }

    static String formatErrorMessage(String errorResponseBody) {
        // See https://www.ietf.org/rfc/rfc6749.txt, section 5.2 for the format
        // of this error message.
        if (errorResponseBody == null || errorResponseBody.trim().isEmpty()) {
            return "{}";
        }
        ObjectMapper mapper = new ObjectMapper();
        try {
            JsonNode rootNode = mapper.readTree(errorResponseBody);
            if (!rootNode.at("/error").isMissingNode()) {
                return String.format("{%s - %s}", rootNode.at("/error"), rootNode.at("/error_description"));
            } else if (!rootNode.at("/errorCode").isMissingNode()) {
                return String.format("{%s - %s}", rootNode.at("/errorCode"), rootNode.at("/errorSummary"));
            } else {
                return errorResponseBody;
            }
        } catch (Exception e) {
            logger.warn("Error parsing error response", e);
        }
        return String.format("{%s}", errorResponseBody);
    }

    static String parseAccessToken(String responseBody) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(responseBody);
        JsonNode accessTokenNode = rootNode.get("access_token");
        JsonNode idTokenNode = rootNode.get("id_token");

        if (accessTokenNode == null && idTokenNode == null) {
            throw new IOException(String.format("The token endpoint response did not contain an access_token or id_token value. Response: (%s)", maybeTrimResponseBody(responseBody)));
        } else if (accessTokenNode != null && idTokenNode != null) {
            throw new IOException(String.format("The token endpoint response contained both an access_token and an id_token value. Response: (%s)", maybeTrimResponseBody(responseBody)));
        } else if (idTokenNode == null) {
            return sanitizeString("the token endpoint response's access_token JSON attribute", accessTokenNode.textValue());
        } else {
            return sanitizeString("the token endpoint response's id_token JSON attribute", idTokenNode.textValue());
        }
    }

    private String createAssertion() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        JwtTokenHeader tokenHeader = new JwtTokenHeader(this.tokenSingingAlgo, "JWT", this.privateKeyId);
        JwtTokenPayload tokenPayload = new JwtTokenPayload(this.tokenIssuer, this.tokenSubject, this.tokenAudience, System.currentTimeMillis() / 1000L, (System.currentTimeMillis() / 1000L) + Duration.ofMinutes(60).toSeconds(), this.tokenTargetAudience);
        String tokenHeaderString = mapper.writeValueAsString(tokenHeader);
        String tokenPayloadString = mapper.writeValueAsString(tokenPayload);
        String base64TokenHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenHeaderString.getBytes(StandardCharsets.UTF_8));
        String base64TokenPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenPayloadString.getBytes(StandardCharsets.UTF_8));

        String contentToSign = base64TokenHeader + "." + base64TokenPayload;
        String signedContent;
        try {
            signedContent = signAssertionWithPrivateKey(contentToSign);
            return contentToSign + "." + signedContent;
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException exception) {
            logger.error("Error signing assertion with private key: {}", exception.getMessage());
        }
        return null;
    }

    private String signAssertionWithPrivateKey(String contentToSign) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature signatureAlgo;
        if (this.tokenSingingAlgo.equals("RS256")) {
            signatureAlgo = Signature.getInstance("SHA256withRSA");
        } else if (this.tokenSingingAlgo.equals("ES256")) {
            signatureAlgo = Signature.getInstance("SHA256withECDSA");
        } else {
            // Shouldn't happen, but here we are
            throw new NoSuchAlgorithmException(String.format("Unsupported signing algorithm: %s", this.tokenSingingAlgo));
        }
        signatureAlgo.initSign(privateKey);
        signatureAlgo.update(contentToSign.getBytes(StandardCharsets.UTF_8));
        byte[] signedContent = signatureAlgo.sign();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signedContent);
    }

    private PrivateKey getPrivateKeyFromSecret(String secret) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(secret);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public String formatRequestBody() {
        try {
            String assertion = createAssertion();
            // TODO Set the grant type somewhere in a config class.
            String encodedGrantType = URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", StandardCharsets.UTF_8);
            String encodedAssertion = URLEncoder.encode(assertion, StandardCharsets.UTF_8);
            return String.format("grant_type=%s&assertion=%s", encodedGrantType, encodedAssertion);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(String.format("Failed to create assertion: %s", e.getMessage()));
        }
    }

    private static String sanitizeString(String name, String value) {
        if (value == null)
            throw new IllegalArgumentException(String.format("The value for %s must be non-null", name));

        if (value.isEmpty())
            throw new IllegalArgumentException(String.format("The value for %s must be non-empty", name));

        value = value.trim();

        if (value.isEmpty())
            throw new IllegalArgumentException(String.format("The value for %s must not contain only whitespace", name));

        return value;
    }

    private static String maybeTrimResponseBody(String responseBody) {
        // Only grab the first N characters so that if the response body is huge, we don't
        // blow up.
        String snippet = responseBody;

        if (snippet.length() > MAX_RESPONSE_BODY_LENGTH) {
            int actualLength = responseBody.length();
            String s = responseBody.substring(0, MAX_RESPONSE_BODY_LENGTH);
            snippet = String.format("%s (trimmed to first %d characters out of %d total)", s, MAX_RESPONSE_BODY_LENGTH, actualLength);
        }

        return snippet;
    }
}