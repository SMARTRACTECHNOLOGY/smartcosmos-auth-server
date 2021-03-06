package net.smartcosmos.cluster.auth.handlers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Returns a 401 error code (Unauthorized) to the client.
 */
@Slf4j
public class AuthUnauthorizedEntryPoint extends LoginUrlAuthenticationEntryPoint {

    public AuthUnauthorizedEntryPoint(String loginFormUrl) {
        super(loginFormUrl);
    }

    /**
     * Always returns a 401 error code to the client.
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        if (StringUtils.startsWithIgnoreCase(request.getContentType(), "text/") || request.getRequestURI().contains("/oauth/")) {
            super.commence(request, response, authException);
        }
        else {
            log.debug("Pre-authenticated entry point called. Rejecting access");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access Denied");
        }
    }
}
