package net.smartcosmos.cluster.auth;

import java.util.Collections;

import org.junit.*;
import org.springframework.cache.concurrent.ConcurrentMapCache;

import net.smartcosmos.security.SecurityResourceProperties;
import net.smartcosmos.security.user.SmartCosmosCachedUser;

import static org.junit.Assert.*;

public class SmartCosmosUserCacheTest {

    private SmartCosmosUserCache userCache;
    private SecurityResourceProperties properties = new SecurityResourceProperties();

    @Before
    public void setUp() throws Exception {

        properties.setCachedUserKeepAliveSecs(2);
        userCache = new SmartCosmosUserCache(new ConcurrentMapCache("SmartCosmosUserCacheTesting", false), properties);
    }

    @Test
    public void thatGetUserFromCacheFindsNoMatchingUser() throws Exception {

        userCache.putUserInCache(new SmartCosmosCachedUser("an-account-urn", "a-user-urn", "testUser", "noPassword", Collections.emptyList()));
        assertTrue(userCache.getUserFromCache("noone") == null);
    }

    @Test
    public void thatGetUserFromCacheFindsMatchingUser() throws Exception {

        String expectedUsername = "expectedUser";
        SmartCosmosCachedUser expectedUser = new SmartCosmosCachedUser("expected-account-urn",
                                                                       "expected-user-urn",
                                                                       expectedUsername,
                                                                       "****",
                                                                       Collections.emptyList());
        userCache.putUserInCache(expectedUser);
        userCache.putUserInCache(new SmartCosmosCachedUser("an-account-urn", "a-user-urn", "testUser", "******", Collections.emptyList()));
        assertTrue(expectedUser.equals(userCache.getUserFromCache(expectedUsername)));
    }

    @Test
    public void thatGetUserFromCacheFindsNoMatchingUserWhenExpired() throws Exception {

        String expiredUsername = "expiredUser";
        SmartCosmosCachedUser expectedUser = new SmartCosmosCachedUser("expired-account-urn",
                                                                       "expired-user-urn",
                                                                       expiredUsername,
                                                                       "****",
                                                                       Collections.emptyList());
        userCache.putUserInCache(expectedUser);
        assertTrue(expectedUser.equals(userCache.getUserFromCache(expiredUsername)));
        Thread.sleep(2500);
        assertTrue(userCache.getUserFromCache(expiredUsername) == null);

    }
}