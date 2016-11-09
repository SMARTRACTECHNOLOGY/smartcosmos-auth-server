package net.smartcosmos.cluster.auth.sign;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Service;

import net.smartcosmos.security.SecurityResourceProperties;

/**
 * @author mgarcia
 */
@EnableConfigurationProperties({ SecurityResourceProperties.class })
@Service
public class SignService {

    private final SecurityResourceProperties securityResourceProperties;

    @Autowired
    public SignService(SecurityResourceProperties securityResourceProperties) {
        this.securityResourceProperties = securityResourceProperties;
    }

    public String sign(String base64Payload) {

        PrivateKey privateKey = new
            KeyStoreKeyFactory(
                securityResourceProperties.getKeystore().getLocation(),
                securityResourceProperties.getKeystore().getPassword())
            .getKeyPair(
                securityResourceProperties.getKeystore().getKeypair(),
                securityResourceProperties.getKeystore().getKeypairPassword())
            .getPrivate();

        Signer signer = new RsaSigner((RSAPrivateKey) privateKey);

        return JwtHelper.encode(base64Payload, signer).getEncoded();
    }
}
