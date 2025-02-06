package io.confluent.oauth.gcp.jwt_bearer;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerClientInitialResponse;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenRetriever;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenValidator;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenValidatorFactory;
import org.apache.kafka.common.security.oauthbearer.internals.secured.JaasOptionsUtils;
import org.apache.kafka.common.security.oauthbearer.internals.secured.ValidateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OAuthBearerLoginCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuthBearerLoginCallbackHandler.class);

    private static final String EXTENSION_PREFIX = "sasl.oauthbearer.sasl.extension.";

    private Map<String, Object> moduleOptions;
    private AccessTokenRetriever accessTokenRetriever;
    private AccessTokenValidator accessTokenValidator;
    private boolean isInitialized = false;

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        moduleOptions = JaasOptionsUtils.getOptions(saslMechanism, jaasConfigEntries);
        AccessTokenRetriever tempAccessTokenRetriever = GcpAccessTokenRetrieverFactory.create(configs, saslMechanism, moduleOptions);
        AccessTokenValidator tempAccessTokenValidator = AccessTokenValidatorFactory.create(configs, saslMechanism);
        init(tempAccessTokenRetriever, tempAccessTokenValidator);
    }

    public void init(AccessTokenRetriever accessTokenRetriever, AccessTokenValidator accessTokenValidator) {
        this.accessTokenRetriever = accessTokenRetriever;
        this.accessTokenValidator = accessTokenValidator;

        try {
            this.accessTokenRetriever.init();
        } catch (IOException e) {
            throw new KafkaException("The OAuth login configuration encountered an error when initializing the AccessTokenRetriever", e);
        }

        isInitialized = true;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        checkInitialized();

        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback) {
                handleTokenCallback((OAuthBearerTokenCallback) callback);
            } else if (callback instanceof SaslExtensionsCallback) {
                handleExtensionsCallback((SaslExtensionsCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    @Override
    public void close() {
        if (accessTokenRetriever != null) {
            try {
                this.accessTokenRetriever.close();
            } catch (IOException e) {
                logger.warn("The OAuth login configuration encountered an error when closing the AccessTokenRetriever", e);
            }
        }
    }

    private void handleTokenCallback(OAuthBearerTokenCallback callback) throws IOException {
        checkInitialized();
        String accessToken = accessTokenRetriever.retrieve();

        try {
            OAuthBearerToken token = accessTokenValidator.validate(accessToken);
            callback.token(token);
        } catch (ValidateException e) {
            logger.warn(e.getMessage(), e);
            callback.error("invalid_token", e.getMessage(), null);
        }
    }

    private void handleExtensionsCallback(SaslExtensionsCallback callback) {
        checkInitialized();

        Map<String, String> extensions = new HashMap<>();

        for (Map.Entry<String, Object> configEntry : this.moduleOptions.entrySet()) {
            String key = configEntry.getKey();

            if (!key.startsWith(EXTENSION_PREFIX))
                continue;

            Object valueRaw = configEntry.getValue();
            String value;

            if (valueRaw instanceof String)
                value = (String) valueRaw;
            else
                value = String.valueOf(valueRaw);

            extensions.put(key.substring(EXTENSION_PREFIX.length()), value);
        }

        SaslExtensions saslExtensions = new SaslExtensions(extensions);

        try {
            OAuthBearerClientInitialResponse.validateExtensions(saslExtensions);
        } catch (SaslException e) {
            throw new ConfigException(e.getMessage());
        }

        callback.extensions(saslExtensions);
    }

    private void checkInitialized() {
        if (!isInitialized)
            throw new IllegalStateException(String.format("To use %s, first call the configure or init method", getClass().getSimpleName()));
    }

}
