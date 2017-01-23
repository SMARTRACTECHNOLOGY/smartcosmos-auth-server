package net.smartcosmos.cluster.auth;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import net.smartcosmos.annotation.EnableSmartCosmosMonitoring;

@SpringBootApplication
@EnableSmartCosmosMonitoring
public class AuthServerApplication extends WebMvcConfigurerAdapter {

    public static void main(String[] args) {

        new SpringApplicationBuilder(AuthServerApplication.class).web(true)
            .run(args);
    }

}
