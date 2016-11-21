package net.smartcosmos.cluster.auth.config;

import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;

/**
 * Configuration for Auth Server.
 */
@Configuration
public class AuthServerconfiguration {

    @Bean
    UserCache userCache() throws Exception {

        return new SpringCacheBasedUserCache(new ConcurrentMapCache("SimpleUserCache", false));
    }
}
