package net.smartcosmos.cluster.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.ConversionService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import net.smartcosmos.cluster.auth.config.SecurityResourceProperties;
import net.smartcosmos.cluster.auth.domain.UserResponse;

/**
 * @author voor
 */
@Service
@Profile("test")
@Qualifier("smartCosmosAuthenticationProvider")
public class TestSmartCosmosAuthenticationProvider
        extends SmartCosmosAuthenticationProvider {

    @Autowired
    public TestSmartCosmosAuthenticationProvider(
        SecurityResourceProperties securityResourceProperties,
        PasswordEncoder passwordEncoder,
        RestTemplate restTemplate,
        UserCache userCache,
        ConversionService conversionService) {

        super(securityResourceProperties, passwordEncoder, restTemplate, userCache, conversionService);
    }

    @Override
    protected UserResponse fetchUser(String username,
            UsernamePasswordAuthenticationToken authentication) {
        return new UserResponse("test", "test", username, "", Arrays.asList("ROLE_USER"));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
            UsernamePasswordAuthenticationToken authentication)
                    throws AuthenticationException {
        return;
    }
}
