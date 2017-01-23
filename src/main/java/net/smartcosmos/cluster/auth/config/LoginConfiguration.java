package net.smartcosmos.cluster.auth.config;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import net.smartcosmos.cluster.auth.filter.CsrfHeaderFilter;
import net.smartcosmos.cluster.auth.handlers.AuthUnauthorizedEntryPoint;
import net.smartcosmos.security.authentication.direct.DirectAccessDeniedHandler;
import net.smartcosmos.security.authentication.direct.EnableDirectHandlers;

@EnableWebSecurity
@Configuration
@EnableDirectHandlers
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class LoginConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    AuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private AuthenticationProvider smartCosmosAuthenticationProvider;

    @Autowired
    LogoutSuccessHandler logoutSuccessHandler;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        final String loginPage = "/login";
        final String logoutPage = "/logout";
        // @formatter:off
            http
                .csrf()
                    .csrfTokenRepository(csrfTokenRepository())
                    .and()
                    .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
                .exceptionHandling()
                    .accessDeniedHandler(new DirectAccessDeniedHandler())
                    .authenticationEntryPoint(new AuthUnauthorizedEntryPoint(loginPage))
                .and()
                .formLogin()
                    .loginPage(loginPage)
                    .permitAll()
                    .usernameParameter("username").passwordParameter("password")
                    .permitAll()
                .and()
                .logout()
                    .logoutUrl(logoutPage)
                    .deleteCookies("JSESSIONID", "CSRF-TOKEN")
                    .permitAll()
                .and()
                .headers()
                    .frameOptions()
                    .disable()
                .and()
                    .antMatcher("/**")
                        .authorizeRequests()
                    .antMatchers(loginPage + "**")
                        .permitAll()
                    .anyRequest()
                        .authenticated();
            // @formatter:on
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.authenticationProvider(smartCosmosAuthenticationProvider)
            .parentAuthenticationManager(authenticationManager);
    }

    private CsrfTokenRepository csrfTokenRepository() {

        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }

    private Filter csrfHeaderFilter() {

        return new CsrfHeaderFilter();
    }
}
