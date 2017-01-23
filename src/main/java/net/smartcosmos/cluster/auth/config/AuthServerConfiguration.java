package net.smartcosmos.cluster.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import net.smartcosmos.cluster.auth.SmartCosmosUserCache;

/**
 * Configuration for Auth Server.
 */
@Configuration
public class AuthServerConfiguration {

    @Bean
    @Autowired
    UserCache userCache(Cache userCache, SecurityResourceProperties securityResourceProperties) throws Exception {

        return new SmartCosmosUserCache(userCache, securityResourceProperties);
    }

    @Bean
    Cache simpleUserCache() {

        return new ConcurrentMapCache("SmartCosmosUserCache", false);
    }

    @Bean
    PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }
}
