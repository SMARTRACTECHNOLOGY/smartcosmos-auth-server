package net.smartcosmos.cluster.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.json.JsonParser;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.stereotype.Service;
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
    private final Map<String, SmartCosmosCachedUser> users = new HashMap<>();
    private String userDetailsServerLocationUri;
    private RestTemplate restTemplate;

    @Autowired
    public SmartCosmosAuthenticationProvider(
        SecurityResourceProperties securityResourceProperties,
        PasswordEncoder passwordEncoder,
        @Qualifier("userDetailsRestTemplate") RestTemplate restTemplate) {

        this.passwordEncoder = passwordEncoder;
        this.restTemplate = restTemplate;

        this.userDetailsServerLocationUri = securityResourceProperties.getUserDetails()
            .getServer()
            .getLocationUri();
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
    protected void additionalAuthenticationChecks(
        UserDetails userDetails,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException {

        if (authentication.getCredentials() == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                "AbstractUserDetailsAuthenticationProvider.badCredentials",
                "Bad credentials"));
        }

        String presentedPassword = authentication.getCredentials()
            .toString();

        if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            logger.debug("Authentication failed: password does not match stored value");

            throw new BadCredentialsException(messages.getMessage(
                "AbstractUserDetailsAuthenticationProvider.badCredentials",
                "Bad credentials"));
        }
    }

    protected UserResponse fetchUser(String username, UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException, OAuth2Exception {

        try {
            return restTemplate.exchange(userDetailsServerLocationUri + "/authenticate",
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
                    // creates a server_error response further on
                    throw new IllegalStateException("Service not properly configured to use credentials", e);
                case BAD_REQUEST:
                    String responseMessage = getErrorResponseMessage(e);
                    if (!StringUtils.isEmpty(responseMessage)) {
                        // creates an invalid_grant OAuthException further on
                        // see org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter
                        // also see https://tools.ietf.org/html/rfc6749#section-5.2
                        throw new BadCredentialsException(responseMessage, e);
                    }
                default:
                    // creates a server_error response further on
                    // see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
                    throw new RuntimeException(defaultIfBlank(getErrorResponseMessage(e), e.getMessage()), e);
            }
        } catch (Exception e) {
            log.debug("Fetching details for user {} with authentication token {} failed: {}", username, authentication, e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    protected UserDetails retrieveUser(
        String username,
        UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException {

        log.debug("Authenticating, {}", username);

        // TODO Improve the caching mechanisms.
        if (users.containsKey(username)) {
            final SmartCosmosCachedUser cachedUser = users.get(username);

            if (System.currentTimeMillis() > cachedUser.getCachedDate()
                .getTime()) {
                users.remove(username);
            } else {
                if (!StringUtils.isEmpty(authentication.getCredentials())
                    && !StringUtils.isEmpty(cachedUser.getPassword())) {
                    if (passwordEncoder.matches(
                        authentication.getCredentials()
                            .toString(),
                        cachedUser.getPassword())) {
                        return cachedUser;
                    }
                }
            }
        }

        UserResponse userResponse = fetchUser(username, authentication);

        log.trace("Received response of: {}", userResponse);

        final SmartCosmosCachedUser user = new SmartCosmosCachedUser(
            userResponse.getTenantUrn(),
            userResponse.getUserUrn(),
            userResponse.getUsername(),
            userResponse.getPasswordHash(),
            userResponse.getAuthorities()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet()));

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
}
