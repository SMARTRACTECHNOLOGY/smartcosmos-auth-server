package net.smartcosmos.cluster.auth.sign;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import net.smartcosmos.annotation.EnableSmartCosmosSecurity;

/**
 * @author mgarcia
 */
@EnableSmartCosmosSecurity
@RestController
public class SignResource {

    private final SignService signService;

    @Autowired
    public SignResource(SignService signService) {
        this.signService = signService;
    }

    @RequestMapping(value = "/sign",
                    method = RequestMethod.POST,
                    produces = MediaType.APPLICATION_JSON_UTF8_VALUE,
                    consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
    @PreAuthorize("hasAuthority('https://authorities.smartcosmos.net/sign')")
    public SignResponse sign(@RequestBody String jwtPayload) {
        String jwt = signService.sign(jwtPayload);
        return new SignResponse(jwt);
    }
}
