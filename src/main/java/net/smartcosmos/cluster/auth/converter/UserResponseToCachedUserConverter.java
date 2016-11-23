package net.smartcosmos.cluster.auth.converter;

import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import net.smartcosmos.cluster.auth.domain.UserResponse;
import net.smartcosmos.security.user.SmartCosmosCachedUser;

/**
 * Convert a {@link UserResponse} to a {@link SmartCosmosCachedUser}.
 */
@Component
public class UserResponseToCachedUserConverter implements Converter<UserResponse, SmartCosmosCachedUser> {

    @Override
    public SmartCosmosCachedUser convert(UserResponse userResponse) {

        SmartCosmosCachedUser user = new SmartCosmosCachedUser(
            userResponse.getTenantUrn(),
            userResponse.getUserUrn(),
            userResponse.getUsername(),
            StringUtils.defaultString(userResponse.getPasswordHash()),
            userResponse.getAuthorities()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet()));

        return user;
    }
}
