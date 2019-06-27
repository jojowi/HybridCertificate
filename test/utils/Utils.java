package utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Utils {

    public static AsymmetricCipherKeyPair createRSAKeyPair() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 4096, 25));
        return gen.generateKeyPair();
    }

    public static AsymmetricCipherKeyPair createQTESLAKeyPair() {
        QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
        try {
            gen.init(new QTESLAKeyGenerationParameters(QTESLASecurityCategory.HEURISTIC_III_SPEED, SecureRandom.getInstanceStrong()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return gen.generateKeyPair();
    }
}
