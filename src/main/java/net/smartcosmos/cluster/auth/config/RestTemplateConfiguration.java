package net.smartcosmos.cluster.auth.config;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.ribbon.RibbonClientHttpRequestFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.InterceptingClientHttpRequestFactory;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;

import net.smartcosmos.security.SecurityResourceProperties;

import static org.apache.commons.lang.CharEncoding.UTF_8;
import static org.apache.http.client.config.AuthSchemes.BASIC;

@Configuration
public class RestTemplateConfiguration {

    @Bean
    @Autowired
    public RestTemplate userDetailsRestTemplate(
        RibbonClientHttpRequestFactory ribbonClientHttpRequestFactory,
        SecurityResourceProperties securityResourceProperties) {

        final String name = securityResourceProperties.getUserDetails()
            .getUser()
            .getName();
        final String password = securityResourceProperties.getUserDetails()
            .getUser()
            .getPassword();

        List<ClientHttpRequestInterceptor> interceptors = Collections.singletonList(new BasicAuthorizationInterceptor(
            name,
            password));

        return new RestTemplate(new InterceptingClientHttpRequestFactory(ribbonClientHttpRequestFactory, interceptors));
    }

    private static class BasicAuthorizationInterceptor implements ClientHttpRequestInterceptor {

        private final String username;
        private final String password;

        BasicAuthorizationInterceptor(String username, String password) {

            this.username = username;
            this.password = (password == null ? "" : password);
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {

            String token = Base64Utils.encodeToString((this.username + ":" + this.password).getBytes(Charset.forName(UTF_8)));
            request.getHeaders()
                .add(HttpHeaders.AUTHORIZATION, BASIC + " " + token);

            return execution.execute(request, body);
        }
    }
}
