package io.confluent.oauth.gcp.jwt_bearer;

import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils;
import org.apache.kafka.common.security.oauthbearer.internals.secured.FileTokenRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.HttpAccessTokenRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.JaasOptionsUtils;

import javax.net.ssl.SSLSocketFactory;
import java.net.URL;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.apache.kafka.common.config.SaslConfigs.SASL_LOGIN_CONNECT_TIMEOUT_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_LOGIN_READ_TIMEOUT_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_LOGIN_RETRY_BACKOFF_MAX_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_LOGIN_RETRY_BACKOFF_MS;
import static org.apache.kafka.common.config.SaslConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL;

public class GcpAccessTokenRetrieverFactory {

    /**
     * Create an {@link AccessTokenRetriever} from the given SASL and JAAS configuration.
     *
     * <b>Note</b>: the returned <code>AccessTokenRetriever</code> is <em>not</em> initialized
     * here and must be done by the caller prior to use.
     *
     * @param configs    SASL configuration
     * @param jaasConfig JAAS configuration
     *
     * @return Non-<code>null</code> {@link AccessTokenRetriever}
     */

    public static AccessTokenRetriever create(Map<String, ?> configs, Map<String, Object> jaasConfig) {
        return create(configs, null, jaasConfig);
    }

    public static AccessTokenRetriever create(Map<String, ?> configs, String saslMechanism, Map<String, Object> jaasConfig) {
        ConfigurationUtils cu = new ConfigurationUtils(configs, saslMechanism);
        URL tokenEndpointUrl = cu.validateUrl(SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL);

        if (tokenEndpointUrl.getProtocol().toLowerCase(Locale.ROOT).equals("file")) {
            return new FileTokenRetriever(cu.validateFile(SASL_OAUTHBEARER_TOKEN_ENDPOINT_URL));
        } else {
            JaasOptionsUtils jou = new JaasOptionsUtils(jaasConfig);
            String tokenEndpointGrantType = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_GRANT_TYPE);

            validateSupportedConfig(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_GRANT_TYPE, tokenEndpointGrantType,
                OAuthBearerConfigs.SUPPORTED_SASL_OAUTHBEARER_TOKEN_ENDPOINT_GRANT_TYPES);

            SSLSocketFactory sslSocketFactory = null;
            if (jou.shouldCreateSSLSocketFactory(tokenEndpointUrl))
                sslSocketFactory = jou.createSSLSocketFactory();

            if (tokenEndpointGrantType.equals("client_credentials")) {
                String clientId = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENPOINT_CLIENT_ID);
                String clientSecret = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENPOINT_CLIENT_SECRET);
                String scope = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_SCOPE, false);

                return new HttpAccessTokenRetriever(clientId,
                    clientSecret,
                    scope,
                    sslSocketFactory,
                    tokenEndpointUrl.toString(),
                    cu.validateLong(SASL_LOGIN_RETRY_BACKOFF_MS),
                    cu.validateLong(SASL_LOGIN_RETRY_BACKOFF_MAX_MS),
                    cu.validateInteger(SASL_LOGIN_CONNECT_TIMEOUT_MS, false),
                    cu.validateInteger(SASL_LOGIN_READ_TIMEOUT_MS, false),
                    true);
            } else if (tokenEndpointGrantType.equals("urn:ietf:params:oauth:grant-type:jwt-bearer")) {
                String signingAlgo = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_SIGNING_ALGO);
                String privateKeyId = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_PRIVATE_KEY_ID);
                String privateKeySecret = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ENDPOINT_PRIVATE_KEY_SECRET);
                String subject = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_SUBJECT);
                String issuer = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_ISSUER);
                String audience = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_AUDIENCE);
                String targetAudience = jou.validateString(OAuthBearerConfigs.SASL_OAUTHBEARER_TOKEN_TARGET_AUDIENCE, false);

                return new GcpAccessTokenRetriever(signingAlgo,
                    privateKeyId,
                    privateKeySecret,
                    subject,
                    issuer,
                    audience,
                    targetAudience,
                    sslSocketFactory,
                    tokenEndpointUrl.toString(),
                    cu.validateLong(SASL_LOGIN_RETRY_BACKOFF_MS),
                    cu.validateLong(SASL_LOGIN_RETRY_BACKOFF_MAX_MS),
                    cu.validateInteger(SASL_LOGIN_CONNECT_TIMEOUT_MS, false),
                    cu.validateInteger(SASL_LOGIN_READ_TIMEOUT_MS, false));
            } else {
                throw new IllegalArgumentException("Unsupported grant type: " + tokenEndpointGrantType);
            }
        }
    }

    private static void validateSupportedConfig(String config, String value, List<String> supportedConfigs) {
        if (value != null && !supportedConfigs.contains(value))
            throw new IllegalArgumentException("Unsupported configuration value: " + config + " for configuration " + config + ". Supported values are: " + supportedConfigs);
    }
}
