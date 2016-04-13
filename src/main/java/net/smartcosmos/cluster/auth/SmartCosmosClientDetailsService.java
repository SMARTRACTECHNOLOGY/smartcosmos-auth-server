package net.smartcosmos.cluster.auth;

import lombok.extern.slf4j.Slf4j;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.client.RestTemplate;

/**
 * @author voor
 */
@Slf4j
public class SmartCosmosClientDetailsService implements ClientDetailsService {

	final private RestTemplate restTemplate;

	public SmartCosmosClientDetailsService(final RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	@Override
	public ClientDetails loadClientByClientId(String clientId)
			throws ClientRegistrationException {
		ParameterizedTypeReference<BaseClientDetails> responseType = new ParameterizedTypeReference<BaseClientDetails>() {
		};

		// Utilizing Ribbon load balancing client and Eureka service discovery to retrieve
		// the client (authorized application) from a micro-service running out of
		// process.
		BaseClientDetails details = this.restTemplate
				.exchange("http://smartcosmos-auth-client-service/{clientId}",
						HttpMethod.GET, null, responseType, (Object) clientId)
				.getBody();

		log.info("Received response: {}", details);

		return details;
	}
}
