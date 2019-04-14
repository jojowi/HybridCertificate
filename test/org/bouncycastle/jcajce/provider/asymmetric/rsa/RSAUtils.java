package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class RSAUtils {

    public static KeyPair toKeyPair(AsymmetricCipherKeyPair pair) {
        RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();
        return new KeyPair(new BCRSAPublicKey(pub), new BCRSAPrivateCrtKey(priv));
    }

    public static AsymmetricCipherKeyPair fromKeyPair(KeyPair pair) {
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) pair.getPrivate();
        RSAKeyParameters pub = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent());
        RSAPrivateCrtKeyParameters priv = new RSAPrivateCrtKeyParameters(
                privateKey.getModulus(),
                privateKey.getPublicExponent(),
                privateKey.getPrivateExponent(),
                privateKey.getPrimeP(),
                privateKey.getPrimeQ(),
                privateKey.getPrimeExponentP(),
                privateKey.getPrimeExponentQ(),
                privateKey.getCrtCoefficient());
        return new AsymmetricCipherKeyPair(pub, priv);
    }
}
