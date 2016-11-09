package net.smartcosmos.cluster.auth.sign;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author mgarcia
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignResponse {

    private String jwt;

}
