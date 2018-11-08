package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.math.BigInteger;
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

    public static AsymmetricCipherKeyPair createRSAKeyPair(String name) {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 4096, 25));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        KeyPair keys = RSAUtils.toKeyPair(pair);
        saveRSAKeyPair(name + "_public", keys.getPublic());
        saveRSAKeyPair(name + "_private", keys.getPrivate());
        return pair;
    }

    public static void saveRSAKeyPair(String Filename, Key key) {
        saveToFile(Filename + ".pem", toPEM(key));
    }

    private static void saveToFile(String filename, String content) {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(new File(filename)));
            writer.write(content);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String toPEM(Object obj) {
        StringWriter sw = new StringWriter();
        JcaPEMWriter pem = new JcaPEMWriter(sw);
        try {
            pem.writeObject(obj);
            pem.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sw.toString();
    }

    public static AsymmetricCipherKeyPair readRSAKeyPair(String name) {
        return RSAUtils.fromKeyPair(new KeyPair(readPublicKeyFromPEMFile(name + "_public"), readPrivateKeyFromPEMFile(name + "_private")));
    }

    private static PublicKey readPublicKeyFromPEMFile(String name) {
        try {
            FileInputStream fis = new FileInputStream(name + ".pem");

            PublicKey pk = null;
            BufferedReader pemReader = new BufferedReader(new InputStreamReader(fis));
            PEMParser pemParser = new PEMParser(pemReader);

            try {
                Object parsedObj = pemParser.readObject();
                if (parsedObj instanceof SubjectPublicKeyInfo) {
                    pk = new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) parsedObj);

                }
            } catch (Exception ex) {
                ex.printStackTrace();
                // System.out.println(ex);
            }
            pemParser.close();
            return pk;
        } catch (Exception e) {
            e.printStackTrace();
            // System.out.println(e);
            return null;
        }
    }

    private static PrivateKey readPrivateKeyFromPEMFile(String name) {
        try {
            FileInputStream fis = new FileInputStream(name + ".pem");

            PrivateKey pk = null;
            BufferedReader pemReader = new BufferedReader(new InputStreamReader(fis));
            PEMParser pemParser = new PEMParser(pemReader);

            try {
                Object parsedObj = pemParser.readObject();
                if (parsedObj instanceof PEMKeyPair) {
                    pk = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) parsedObj).getPrivate();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            pemParser.close();

            return pk;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
