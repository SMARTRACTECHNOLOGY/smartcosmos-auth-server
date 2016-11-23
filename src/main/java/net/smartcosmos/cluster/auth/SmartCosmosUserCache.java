package net.smartcosmos.cluster.auth;

import lombok.extern.slf4j.Slf4j;

import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;

import net.smartcosmos.security.SecurityResourceProperties;
import net.smartcosmos.security.user.SmartCosmosCachedUser;

/**
 * A Spring Security based cache for {@link SmartCosmosCachedUser}s.
 * <p>
 * This cache will interrogate the cached user's cachedDate and determine if it is older than now() minus the cache expiration
 * time.  If the expiration time duration has been exceeded then the user is removed from the cache and null is returned. This
 * will force Spring Security to fetch a new user from the User Details service.
 * </p>
 * <p>
 * The {@code cachedUserExpirationTime} defaults to the {@link SecurityResourceProperties}.DEFAULT_CACHED_USER_KEEP_ALIVE_SECS
 * and is set from the {@code smartcosmos.security.resource.cachedUserKeepAliveSecs} configuration property.
 * </p>
 *
 */
@Slf4j
public class SmartCosmosUserCache extends SpringCacheBasedUserCache {

    private Duration cachedUserExpirationTime = Duration.millis(SecurityResourceProperties.DEFAULT_CACHED_USER_KEEP_ALIVE_SECS * 1000);

    /**
     * Create an instance of the user cache.
     * <p>
     * This cache is a simple cache implementation that adds expiration to the {@code SpringCacheBasedUserCache}.  On fetch if
     * the time a a user has been in the cache exceeds the expiration time the user is ejected from the cache and a null is returned.
     * </p>
     *
     * @param cache the embedded cache inside this user cache
     * @param securityResourceProperties configuration properties containing the number of millseconds a user is kept in the cache
     * @throws Exception something has gone horribly wrong
     */
    @Autowired
    public SmartCosmosUserCache(Cache cache, SecurityResourceProperties securityResourceProperties) throws Exception {

        super(cache);
        this.cachedUserExpirationTime = Duration.millis(securityResourceProperties.getCachedUserKeepAliveSecs() * 1000);
        log.debug("User cache initialized.");
    }

    @Override
    public UserDetails getUserFromCache(String username) {

        SmartCosmosCachedUser cachedUser = (SmartCosmosCachedUser) super.getUserFromCache(username);
        if (cachedUser != null) {
            Duration userCachedDuration = new Duration(cachedUser.getCachedDate().getTime(), DateTime.now().getMillis());

            if (userCachedDuration.isShorterThan(cachedUserExpirationTime)) {
                return cachedUser;
            }

            removeUserFromCache(cachedUser);
        }

        return null;
    }
}
