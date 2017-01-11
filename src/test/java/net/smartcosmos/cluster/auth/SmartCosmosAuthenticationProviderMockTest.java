package net.smartcosmos.cluster.auth;

import java.security.Principal;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.core.convert.ConversionService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.RestTemplate;

import net.smartcosmos.cluster.auth.config.SecurityResourceProperties;

import static org.junit.Assert.*;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SmartCosmosAuthenticationProviderMockTest {

    private final String USERNAME = "someUsername";
    private final String PASSWORD = "somePassword";

    @Spy
    SecurityResourceProperties securityResourceProperties = new SecurityResourceProperties();

    @Spy
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Mock
    RestTemplate restTemplate;

    @Mock
    UserCache userCache;

    @Mock
    ConversionService conversionService;

    @InjectMocks
    SmartCosmosAuthenticationProvider authenticationProvider;

    @Mock
    UserDetails userDetails;

    @Mock
    Principal principal;

    @Test
    public void thatMockingWorks() {

        assertNotNull(securityResourceProperties);
        assertNotNull(passwordEncoder);
        assertNotNull(restTemplate);
        assertNotNull(userCache);
        assertNotNull(conversionService);
        assertNotNull(authenticationProvider);

        assertNotNull(userDetails);
        assertNotNull(principal);
    }

    @Before
    public void setUp() {

        when(userDetails.getUsername()).thenReturn(USERNAME);
        when(userDetails.getPassword()).thenReturn(PASSWORD);
    }

    @After
    public void tearDown() {

        reset(securityResourceProperties, passwordEncoder, restTemplate, userCache, conversionService, userDetails);
    }

    // region additionalAuthenticationChecks()

    @Test(expected = AuthenticationException.class)
    public void thatAdditionalAuthenticationChecksThrowsAuthenticationExceptionForMissingCredentials() {

        final String credentials = null;

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, credentials);

        authenticationProvider.additionalAuthenticationChecks(userDetails, authentication);
    }

    @Test
    public void thatAdditionalAuthenticationChecksDoesNotCheckUserDetailsPasswordForMissingCredentials() {

        final String credentials = null;

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, credentials);

        try {
            authenticationProvider.additionalAuthenticationChecks(userDetails, authentication);
        } catch (Exception e) {
            // swallow the exception so that we can verify the mock interactions
        }

        verify(userDetails, times(1)).getUsername();
        verifyNoMoreInteractions(userDetails);
        verifyZeroInteractions(passwordEncoder);
    }

    @Test(expected = AuthenticationException.class)
    public void thatAdditionalAuthenticationChecksThrowsAuthenticationExceptionForBadCredentials() {

        final String credentials = "password";

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, credentials);

        authenticationProvider.additionalAuthenticationChecks(userDetails, authentication);
    }

    // endregion
}
