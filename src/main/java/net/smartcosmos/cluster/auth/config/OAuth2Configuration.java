package net.smartcosmos.cluster.auth.config;

import java.security.KeyPair;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.Assert;

import net.smartcosmos.cluster.auth.SmartCosmosAuthenticationProvider;
import net.smartcosmos.security.user.SmartCosmosUserAuthenticationConverter;

@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties({ SecurityResourceProperties.class })
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private SecurityResourceProperties securityResourceProperties;

    @Autowired
    private SmartCosmosAuthenticationProvider smartCosmosAuthenticationProvider;

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {

        Assert.hasText(securityResourceProperties.getKeystore()
                           .getKeypair());
        Assert.notNull(securityResourceProperties.getKeystore()
                           .getLocation());

        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        SmartCosmosUserAuthenticationConverter smartCosmosUserAuthenticationConverter = new SmartCosmosUserAuthenticationConverter();

        ((DefaultAccessTokenConverter) converter.getAccessTokenConverter())
            .setUserTokenConverter(smartCosmosUserAuthenticationConverter);
        KeyPair keyPair = new KeyStoreKeyFactory(
            securityResourceProperties.getKeystore()
                .getLocation(),
            securityResourceProperties.getKeystore()
                .getPassword()).getKeyPair(
            securityResourceProperties.getKeystore()
                .getKeypair(),
            securityResourceProperties.getKeystore()
                .getKeypairPassword());
        converter.setKeyPair(keyPair);
        return converter;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory()
            // TODO This is just here for development purposes.
            .withClient(securityResourceProperties.getClientId())
            .secret(securityResourceProperties.getClientSecret())
            .accessTokenValiditySeconds(securityResourceProperties.getAccessTokenValiditySecs())
            .refreshTokenValiditySeconds(securityResourceProperties.getRefreshTokenValiditySecs())
            .authorizedGrantTypes("authorization_code", "refresh_token",
                                  "implicit", "password", "client_credentials")
            .scopes("read", "write");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
        throws Exception {

        endpoints
            .authenticationManager(new ProviderManager(Arrays.asList(smartCosmosAuthenticationProvider)))
            .userDetailsService(smartCosmosAuthenticationProvider)
            .accessTokenConverter(jwtAccessTokenConverter());
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer)
        throws Exception {

        oauthServer.tokenKeyAccess("permitAll()")
            .checkTokenAccess("isAuthenticated()");
    }

}
