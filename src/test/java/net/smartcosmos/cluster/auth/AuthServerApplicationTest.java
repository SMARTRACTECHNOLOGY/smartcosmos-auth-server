package net.smartcosmos.cluster.auth;

import java.net.URI;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.client.config.AuthSchemes;
import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AuthServerApplication.class)
@WebAppConfiguration
@IntegrationTest({ "server.port=0", "spring.cloud.config.enabled=false" })
@ActiveProfiles("test")
public class AuthServerApplicationTest {

    @Value("${local.server.port}")
    private int port;

    private RestTemplate template = new TestRestTemplate();

    @Test
    public void homePageProtected() {

        ResponseEntity<String> response = template.getForEntity("http://localhost:"
                                                                + port, String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    public void authorizationRedirects() {

        ResponseEntity<String> response = template.getForEntity("http://localhost:"
                                                                + port + "/oauth/authorize", String.class);
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        String location = response.getHeaders()
            .getFirst("Location");
        assertTrue("Wrong header: " + location,
                   location.startsWith("http://localhost:" + port + "/login"));
    }

    @Test
    public void loginSucceeds() {

        ResponseEntity<String> response = template.getForEntity("http://localhost:"
                                                                + port + "/login", String.class);
        String csrf = getCsrf(response.getBody());
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set("username", "user");
        form.set("password", "password");
        form.set("_csrf", csrf);
        HttpHeaders headers = new HttpHeaders();
        headers.put("COOKIE",
                    response.getHeaders()
                        .get("Set-Cookie"));

        RequestEntity<MultiValueMap<String, String>> request = new RequestEntity<>(
            form, headers, HttpMethod.POST, URI.create("http://localhost:" + port
                                                       + "/login"));
        ResponseEntity<Void> location = template.exchange(request, Void.class);
        assertEquals(HttpStatus.FOUND, location.getStatusCode());
        assertEquals("http://localhost:" + port + "/",
                     location.getHeaders()
                         .getFirst("Location"));
    }

    @Test
    public void thatMissingServiceCredentialsReturnUnauthorized() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    public void thatWrongServiceCredentialsReturnUnauthorized() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "invalid"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    public void thatProperServiceCredentialsReturnOk() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "password"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void thatTokenAcquisitionReturnsResponseBody() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "password"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);

        assertTrue(response.hasBody());
    }

    @Test
    public void thatTokenAcquisitionReturnsAccessToken() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "password"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);
        Map<String, Object> responseBody = response.getBody();

        assertTrue(responseBody.containsKey("access_token"));
    }

    @Test
    public void thatTokenAcquisitionReturnsRefreshToken() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "password"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);
        Map<String, Object> responseBody = response.getBody();

        assertTrue(responseBody.containsKey("refresh_token"));
    }

    @Test
    public void thatTokenAcquisitionReturnsTokenType() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "password"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);
        Map<String, Object> responseBody = response.getBody();

        assertTrue(responseBody.containsKey("token_type"));
    }

    @Test
    public void thatTokenAcquisitionReturnsBearerToken() {

        URI requestUri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port)
            .path("oauth/token")
            .queryParam("grant_type", "password")
            .queryParam("scope", "read")
            .queryParam("username", "someUsername")
            .queryParam("password", "somePassword")
            .build()
            .toUri();

        RequestEntity requestEntity = RequestEntity.post(requestUri)
            .header(HttpHeaders.AUTHORIZATION, getBasicAuth("user", "password"))
            .build();
        ResponseEntity<Map> response = template.exchange(requestEntity, Map.class);
        Map<String, Object> responseBody = response.getBody();

        assertEquals("bearer", responseBody.get("token_type"));
    }

    // region Helpers

    private String getCsrf(String soup) {

        Matcher matcher = Pattern.compile("(?s).*name=\"_csrf\".*?value=\"([^\"]+).*")
            .matcher(soup);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        return null;
    }

    private String getBasicAuth(String username, String password) {

        String credentialString = username + ":" + password;
        return AuthSchemes.BASIC + " " + Base64.getEncoder()
            .encodeToString(credentialString.getBytes());
    }

    // endregion
}
