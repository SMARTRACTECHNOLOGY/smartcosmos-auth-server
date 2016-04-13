package net.smartcosmos.cluster.auth;

import java.security.KeyPair;

import lombok.extern.slf4j.Slf4j;
import net.smartcosmos.security.SecurityResourceProperties;
import net.smartcosmos.security.authentication.direct.DirectAccessDeniedHandler;
import net.smartcosmos.security.authentication.direct.DirectUnauthorizedEntryPoint;
import net.smartcosmos.security.user.SmartCosmosUserAuthenticationConverter;
import net.smartcosmos.spring.EnableSmartCosmosSecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * @author voor
 */
@SpringBootApplication
@Controller
@SessionAttributes("authorizationRequest")
@Slf4j
@EnableDiscoveryClient
public class AuthServerApplication extends WebMvcConfigurerAdapter {

	public static void main(String[] args) {
		new SpringApplicationBuilder(AuthServerApplication.class).web(true).run(args);
	}

	@Bean
	@Primary
	public AuthenticationManager authenticationManager(
			AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
		registry.addViewController("/oauth/confirm_access").setViewName("authorize");
	}

	@Configuration
	@EnableGlobalAuthentication
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER - 3)
	protected static class GlobalAuthenticationConfig
			extends GlobalAuthenticationConfigurerAdapter {

		@Autowired
		private SmartCosmosAuthenticationProvider smartCosmosAuthenticationProvider;

		@Bean
		PasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			log.info("Adding in customer user details authentication provider");
			auth.authenticationProvider(smartCosmosAuthenticationProvider);
		}
	}

	@EnableWebSecurity
	@Configuration
	@EnableSmartCosmosSecurity
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	protected static class LoginConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		AuthenticationSuccessHandler authenticationSuccessHandler;

		@Autowired
		AuthenticationFailureHandler authenticationFailureHandler;

		@Autowired
		LogoutSuccessHandler logoutSuccessHandler;

		@Autowired
		private AuthenticationManager authenticationManager;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().and().exceptionHandling()
					.accessDeniedHandler(new DirectAccessDeniedHandler())
					.authenticationEntryPoint(new DirectUnauthorizedEntryPoint()).and()
					.httpBasic();
			// .formLogin()
			// .loginProcessingUrl("/authentication")
			// .successHandler(authenticationSuccessHandler)
			// .failureHandler(authenticationFailureHandler)
			// .usernameParameter("username")
			// .passwordParameter("password")
			// .permitAll()
			// .and()
			// .logout()
			// .logoutUrl("/logout")
			// .logoutSuccessHandler(logoutSuccessHandler)
			// .deleteCookies("JSESSIONID", "CSRF-TOKEN")
			// .permitAll()
			// .and()
			// .headers()
			// .frameOptions()
			// .disable()
			// .and()
			// .authorizeRequests()
			// .antMatchers("/oauth/**").permitAll()
			// .anyRequest().authenticated();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.parentAuthenticationManager(authenticationManager);
		}
	}

	@Configuration
	@EnableAuthorizationServer
	@EnableConfigurationProperties({ SecurityResourceProperties.class })
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private SecurityResourceProperties securityResourceProperties;

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private SmartCosmosUserAuthenticationConverter smartCosmosUserAuthenticationConverter;

		@Autowired
		private SmartCosmosAuthenticationProvider smartCosmosAuthenticationProvider;

		@Bean
		public JwtAccessTokenConverter jwtAccessTokenConverter() {
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			smartCosmosUserAuthenticationConverter
					.setUserDetailsService(smartCosmosAuthenticationProvider);
			((DefaultAccessTokenConverter) converter.getAccessTokenConverter())
					.setUserTokenConverter(smartCosmosUserAuthenticationConverter);
			log.info("JWT Access Token Location {}, keypair name {}",
					securityResourceProperties.getKeystore().getLocation(),
					securityResourceProperties.getKeystore().getKeypair());
			KeyPair keyPair = new KeyStoreKeyFactory(
					securityResourceProperties.getKeystore().getLocation(),
					securityResourceProperties.getKeystore().getPassword()).getKeyPair(
							securityResourceProperties.getKeystore().getKeypair(),
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
					.authorizedGrantTypes("authorization_code", "refresh_token",
							"implicit", "password", "client_credentials")
					.scopes("read", "write");
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints)
				throws Exception {
			endpoints.authenticationManager(authenticationManager)
					.accessTokenConverter(jwtAccessTokenConverter());
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer)
				throws Exception {
			oauthServer.tokenKeyAccess("permitAll()")
					.checkTokenAccess("isAuthenticated()");
		}

	}
}
