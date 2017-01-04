package net.smartcosmos.cluster.auth.sign;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

import javax.security.auth.DestroyFailedException;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Service;

import net.smartcosmos.cluster.auth.config.SecurityResourceProperties;

/**
 * @author mgarcia
 */
@Slf4j
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

        try {
            Signer signer = new RsaSigner((RSAPrivateKey) privateKey);
            return JwtHelper.encode(base64Payload, signer).getEncoded();
        } finally {
            try {
                privateKey.destroy();
            } catch (DestroyFailedException e) {
                log.warn("Failed to destroy key", e);
            }
        }

    }
}
