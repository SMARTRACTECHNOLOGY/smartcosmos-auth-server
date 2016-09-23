package net.smartcosmos.cluster.auth;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.json.JsonParser;
import org.springframework.cloud.netflix.ribbon.RibbonClientHttpRequestFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.InterceptingClientHttpRequestFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import net.smartcosmos.cluster.auth.domain.UserResponse;
import net.smartcosmos.security.SecurityResourceProperties;
import net.smartcosmos.security.user.SmartCosmosCachedUser;

import static org.apache.commons.lang.StringUtils.defaultIfBlank;

@Slf4j
@Service
@Profile("!test")
@EnableConfigurationProperties({ SecurityResourceProperties.class })
public class SmartCosmosAuthenticationProvider
        extends AbstractUserDetailsAuthenticationProvider implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final RibbonClientHttpRequestFactory ribbonClientHttpRequestFactory;
    private final SecurityResourceProperties securityResourceProperties;
    private final Map<String, SmartCosmosCachedUser> users = new HashMap<>();
    private String userDetailsServerLocationUri;
    private RestTemplate restTemplate;

    @Autowired
    public SmartCosmosAuthenticationProvider(
            RibbonClientHttpRequestFactory ribbonClientHttpRequestFactory,
            SecurityResourceProperties securityResourceProperties,
            PasswordEncoder passwordEncoder) {
        this.ribbonClientHttpRequestFactory = ribbonClientHttpRequestFactory;
        this.securityResourceProperties = securityResourceProperties;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void init() {
        this.userDetailsServerLocationUri = securityResourceProperties.getUserDetails()
                .getServer().getLocationUri();
        final String name = securityResourceProperties.getUserDetails().getUser()
                .getName();
        final String password = securityResourceProperties.getUserDetails().getUser()
                .getPassword();
        List<ClientHttpRequestInterceptor> interceptors = Collections
                .<ClientHttpRequestInterceptor> singletonList(
                        new BasicAuthorizationInterceptor(name, password));
        restTemplate = new RestTemplate(new InterceptingClientHttpRequestFactory(
                ribbonClientHttpRequestFactory, interceptors));
    }

    /**
     * This is where the password is actually checked for caching purposes. Assuming the
     * same password encoder was used on both the user details service and here, this will
     * avoid another round trip for authentication.
     *
     * @param userDetails the recently retrieved or previously cached details.
     * @param authentication the presented token for authentication
     * @throws AuthenticationException failure to authenticate.
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication)
                    throws AuthenticationException {

        if (authentication.getCredentials() == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }

        String presentedPassword = authentication.getCredentials().toString();

        if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            logger.debug("Authentication failed: password does not match stored value");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
    }

    protected UserResponse fetchUser(
        String username,
        UsernamePasswordAuthenticationToken authentication) throws AuthenticationException, OAuth2Exception {

        try {
            return this.restTemplate
                .exchange(userDetailsServerLocationUri + "/authenticate",
                          HttpMethod.POST, new HttpEntity<Object>(authentication),
                          UserResponse.class, username)
                .getBody();
        } catch (HttpStatusCodeException e) {
            log.debug("Fetching details for user {} with authentication token {} failed: {} - {}",
                      username,
                      authentication,
                      e.toString(),
                      e.getResponseBodyAsString());
            switch (e.getStatusCode()) {
                case UNAUTHORIZED:
                    log.warn(
                        "Auth Server or User Details Service not properly configured to use SMART COSMOS Security Credentials; all requests will "
                        + "fail.");
                    // creates an invalid_client OAuthException further on
                    throw new InvalidClientException("Invalid client credentials for user details service");
                case BAD_REQUEST:
                    String responseMessage = getErrorResponseMessage(e);
                    if (!StringUtils.isEmpty(responseMessage)) {
                        // creates an invalid_grant OAuthException further on
                        // see org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter
                        throw new BadCredentialsException(responseMessage, e);
                    }
                    throw new InternalAuthenticationServiceException(e.getMessage(), e);
                case INTERNAL_SERVER_ERROR:
                    throw new InternalAuthenticationServiceException(defaultIfBlank(getErrorResponseMessage(e),
                                                                                    e.getMessage()), e);
                default:
                    throw new InternalAuthenticationServiceException(e.getMessage(), e);
            }
        } catch (Exception e) {
            log.debug("Fetching details for user {} with authentication token {} failed: {}", username, authentication, e);
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        }
    }

    @Override
    protected UserDetails retrieveUser(String username,
            UsernamePasswordAuthenticationToken authentication)
                    throws AuthenticationException {

        log.debug("Authenticating, {}", username);

        // TODO Improve the caching mechanisms.
        if (users.containsKey(username)) {
            final SmartCosmosCachedUser cachedUser = users.get(username);

            if (System.currentTimeMillis() > cachedUser.getCachedDate().getTime()) {
                users.remove(username);
            }
            else {
                if (!StringUtils.isEmpty(authentication.getCredentials())
                        && !StringUtils.isEmpty(cachedUser.getPassword())) {
                    if (passwordEncoder.matches(
                            authentication.getCredentials().toString(),
                            cachedUser.getPassword())) {
                        return cachedUser;
                    }
                }
            }
        }

        UserResponse userResponse = fetchUser(username,authentication);

        log.trace("Received response of: {}", userResponse);

        final SmartCosmosCachedUser user = new SmartCosmosCachedUser(
                userResponse.getTenantUrn(), userResponse.getUserUrn(), userResponse.getUsername(),
                userResponse.getPasswordHash(), userResponse.getAuthorities().stream()
                        .map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));

        users.put(userResponse.getUsername(), user);

        return user;
    }

    /**
     * This method will retrieve a user from a quasi-user details service. Except this
     * service is never used for actual authentication
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        if (!users.containsKey(username)) {
            throw new UsernameNotFoundException("Could not find " + username
                    + " in the cache, did the user never properly authenticate?");
        }
        return users.get(username);
    }

    private String getErrorResponseMessage(HttpStatusCodeException exception) {

        MediaType contentType = exception.getResponseHeaders()
            .getContentType();
        if (MediaType.APPLICATION_JSON.equals(contentType) || MediaType.APPLICATION_JSON_UTF8.equals(contentType)) {
            JsonParser jsonParser = new JacksonJsonParser();
            Map<String, Object> responseBody = jsonParser.parseMap(exception.getResponseBodyAsString());
            if (responseBody.containsKey("message") && responseBody.get("message") instanceof String) {
                return (String) responseBody.get("message");
            }
        }
        return "";
    }

    private static class BasicAuthorizationInterceptor
            implements ClientHttpRequestInterceptor {

        private final String username;

        private final String password;

        BasicAuthorizationInterceptor(String username, String password) {
            this.username = username;
            this.password = (password == null ? "" : password);
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                ClientHttpRequestExecution execution) throws IOException {
            String token = Base64Utils
                    .encodeToString((this.username + ":" + this.password)
                            .getBytes(Charset.forName("UTF-8")));
            request.getHeaders().add("Authorization", "Basic " + token);
            return execution.execute(request, body);
        }

    }
}
