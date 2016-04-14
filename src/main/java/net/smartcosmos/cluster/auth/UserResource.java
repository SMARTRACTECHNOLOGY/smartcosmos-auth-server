package net.smartcosmos.cluster.auth;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author voor
 */
@RestController
public class UserResource {
    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }
}
