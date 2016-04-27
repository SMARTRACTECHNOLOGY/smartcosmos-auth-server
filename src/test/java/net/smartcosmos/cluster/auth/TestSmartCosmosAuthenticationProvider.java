package net.smartcosmos.cluster.auth;

import net.smartcosmos.cluster.auth.domain.UserResponse;
import net.smartcosmos.security.SecurityResourceProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.netflix.ribbon.RibbonClientHttpRequestFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

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
            RibbonClientHttpRequestFactory ribbonClientHttpRequestFactory,
            SecurityResourceProperties securityResourceProperties,
            PasswordEncoder passwordEncoder) {
        super(ribbonClientHttpRequestFactory, securityResourceProperties,
                passwordEncoder);
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
