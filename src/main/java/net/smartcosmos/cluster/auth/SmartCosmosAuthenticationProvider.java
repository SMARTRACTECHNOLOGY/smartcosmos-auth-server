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
import net.smartcosmos.cluster.auth.domain.UserDto;
import net.smartcosmos.security.SecurityResourceProperties;
import net.smartcosmos.security.user.SmartCosmosCachedUser;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.ribbon.RibbonClientHttpRequestFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
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
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * @author voor
 */
@Slf4j
@Service
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

	@Override
	protected UserDetails retrieveUser(String username,
			UsernamePasswordAuthenticationToken authentication)
					throws AuthenticationException {

		log.info("Authenticating, {}", username);

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

		UserDto userDto = null;
		try {
			userDto = this.restTemplate
					.exchange(userDetailsServerLocationUri + "/{username}",
							HttpMethod.POST, new HttpEntity<Object>(authentication),
							UserDto.class, username)
					.getBody();
		}
		catch (HttpClientErrorException e) {
			if (HttpStatus.UNAUTHORIZED.equals(e.getStatusCode())) {
				log.debug(
						"User Details Service not properly configured to use SMART COSMOS Security Credentials; all requests will fail.");
				throw new InternalAuthenticationServiceException(e.getMessage(), e);
			}
			else {
				throw new InternalAuthenticationServiceException(e.getMessage(), e);
			}
		}
		catch (Exception e) {
			log.debug("InternalAuthenticationServiceException", e);
			throw new InternalAuthenticationServiceException(e.getMessage(), e);
		}

		log.info("Received response of: {}", userDto);

		final SmartCosmosCachedUser user = new SmartCosmosCachedUser(
				userDto.getAccountUrn(), userDto.getUserUrn(), userDto.getUsername(),
				userDto.getPasswordHash(), userDto.getRoles().stream()
						.map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));

		users.put(userDto.getUsername(), user);

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
