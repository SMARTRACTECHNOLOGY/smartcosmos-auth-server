package net.smartcosmos.cluster.auth.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;

/**
 * This is the response from the User Details Service that will contain the necessary
 * information for caching purposes. While not required, if the password hash is filled
 * this will speed up authentication considerably, since it can be queried against the
 * native Spring Security Cache.
 *
 * @author voor
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "passwordHash")
public class UserResponse {

    private String accountUrn;

    private String userUrn;

    private String username;

    private String passwordHash;

    private List<String> roles;
}
