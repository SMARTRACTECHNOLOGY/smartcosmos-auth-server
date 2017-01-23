package net.smartcosmos.cluster.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@SessionAttributes("authorizationRequest")
public class ViewControllerConfiguration extends WebMvcConfigurerAdapter {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {

        registry.addViewController("/login")
            .setViewName("login");
        registry.addViewController("/oauth/confirm_access")
            .setViewName("authorize");
    }
}
