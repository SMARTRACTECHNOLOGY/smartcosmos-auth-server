package net.smartcosmos.cluster.auth;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author voor
 */
@RestController
public class UserResource {

    @RequestMapping({ "/user", "/me" })
    public Map<String, String> user(Principal principal) {

        Map<String, String> map = new LinkedHashMap<>();
        if (principal != null) {
            map.put("name", principal.getName());
        }
        return map;
    }
}
