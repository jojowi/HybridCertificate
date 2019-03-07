
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtils;
import org.bouncycastle.jce.provider.HybridCertPathValidatorResult;
import org.bouncycastle.jce.provider.HybridCertPathValidatorSpi;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.qtesla.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

/**
 * Example code for using the hybrid certificate functionality
 */
public class Main {
    public static void main(String[]args) throws IOException, CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {


        AsymmetricCipherKeyPair CA1sec = createQTESLAKeyPair("CA1");
        AsymmetricCipherKeyPair CA2sec = createQTESLAKeyPair("CA2");
        AsymmetricCipherKeyPair EEsec = createQTESLAKeyPair("EE");
        AsymmetricCipherKeyPair CA1 = createRSAKeyPair("CA1");
        AsymmetricCipherKeyPair CA2 = createRSAKeyPair("CA2");
        AsymmetricCipherKeyPair EE = createRSAKeyPair("EE");

        createCert("CA1", "CA1");
        createCert("CA2", "CA1");
        createCert("EE", "CA2");

        X509Certificate ca1 = readCertificate("CA1.crt");
        X509Certificate ca2 = readCertificate("CA1-CA2.crt");
        X509Certificate ee = readCertificate("CA2-EE.crt");

        QTESLASigner verify = new QTESLASigner();
        verify.init(false, QTESLAUtils.fromSubjectPublicKeyInfo(HybridKey.fromCert(ca1).getKey()));
        System.out.println(verify.verifySignature(HybridCertUtils.extractBaseCertSearch(ca2), HybridSignature.fromCert(ca2).getSignature()));

        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(ee);
        certificates.add(ca2);
        certificates.add(ca1);
        TrustAnchor anchor = new TrustAnchor(ca1, null);

        HybridCertUtils.extractBaseCertSearch(ca1);
        HybridCertUtils.extractBaseCertSearch(ca2);
        HybridCertUtils.extractBaseCertSearch(ee);
        verifyCertPath(certificates);


        ca1 = readCertificate("ca1.cert.pem");
        ca2 = readCertificate("intermediate.cert.pem");
        ee = readCertificate("client.cert.pem");

        verify = new QTESLASigner();
        verify.init(false, QTESLAUtils.fromSubjectPublicKeyInfo(HybridKey.fromCert(ca1).getKey()));
        certificates = new LinkedList<>();
        certificates.add(ee);
        certificates.add(ca2);
        certificates.add(ca1);
        anchor = new TrustAnchor(ca1, null);
        verifyCertPath(certificates);
    }

    /**
     * Try to verify a hybrid end entity certificate
     *
     * @param certificates the certification path, starting with the end entity and ending with the trust anchor
     */
    private static void verifyCertPath(List<X509Certificate> certificates) throws CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath certPath = factory.generateCertPath(certificates);
        HybridCertPathValidatorSpi validator = new HybridCertPathValidatorSpi();
        TrustAnchor anchor = new TrustAnchor(certificates.get(certificates.size() - 1), null);
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(anchor);
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);
        HybridCertPathValidatorResult result = validator.engineValidate(certPath, params);
        System.out.println(result.isHybridChainValidated());
    }

    private static void createCert(String subject, String issuer) {
        AsymmetricCipherKeyPair primary = readRSAKeyPair(subject);
        AsymmetricCipherKeyPair primarySigner = readRSAKeyPair(issuer);
        AsymmetricCipherKeyPair secondary = readQTESLAKeyPair(subject);
        AsymmetricCipherKeyPair secondarySigner = readQTESLAKeyPair(issuer);

        X509Certificate cert = createCertificate(subject, issuer, primary, secondary, primarySigner.getPrivate(), secondarySigner.getPrivate());
        saveCertificateAsPEM(cert, issuer.equals(subject) ? issuer : issuer + "-" + subject);
        //System.out.println(ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(cert.getTBSCertificate())));
    }

    private static AsymmetricCipherKeyPair createRSAKeyPair(String name) {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 4096, 25));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        KeyPair keys = RSAUtils.toKeyPair(pair);
        saveRSAKeyPair(name + "_public", keys.getPublic());
        saveRSAKeyPair(name + "_private", keys.getPrivate());
        return pair;
    }

    private static AsymmetricCipherKeyPair readRSAKeyPair(String name) {
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

    private static void saveRSAKeyPair(String Filename, Key key) {
        saveToFile(Filename + ".pem", toPEM(key));
    }

    private static AsymmetricCipherKeyPair createQTESLAKeyPair(String name) {
        QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
        try {
            gen.init(new QTESLAKeyGenerationParameters(QTESLASecurityCategory.HEURISTIC_III_SPEED, SecureRandom.getInstanceStrong()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        try {
            File file = new File(name + "_public.key");
            FileOutputStream out = new FileOutputStream(file);
            //out.write(QTESLAUtils.toASN1Primitive((QTESLAPublicKeyParameters) pair.getPublic()).getEncoded());
            out.write(((QTESLAPublicKeyParameters)pair.getPublic()).getPublicData());
            out.close();
            file = new File(name + "_private.key");
            out = new FileOutputStream(file);
            out.write(QTESLAUtils.toASN1Primitive((QTESLAPrivateKeyParameters) pair.getPrivate()).getEncoded());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pair;
    }

    private static AsymmetricCipherKeyPair readQTESLAKeyPair(String name) {
        try {
            File file = new File(name + "_public.key");
            FileInputStream in = new FileInputStream(file);
            QTESLAPublicKeyParameters pub = QTESLAUtils.fromASN1Primitive(in.readAllBytes(), QTESLASecurityCategory.HEURISTIC_III_SPEED);
            in.close();
            file = new File(name + "_private.key");
            in = new FileInputStream(file);
            QTESLAPrivateKeyParameters priv = QTESLAUtils.fromASN1PrimitivePrivate(in.readAllBytes(), QTESLASecurityCategory.HEURISTIC_III_SPEED);
            in.close();
            return new AsymmetricCipherKeyPair(pub, priv);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static X509Certificate readCertificate(String name) {
        try {
            FileInputStream fis = new FileInputStream(name);
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate c = cf.generateCertificate(bis);
            bis.close();
            fis.close();
            return (X509Certificate) c;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static X509Certificate createCertificate(String subject, String issuer, AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair secondary, AsymmetricKeyParameter primarySigner, AsymmetricKeyParameter secondarySigner) {
        try {
            DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withRSA");
            AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

            Calendar calendar = new GregorianCalendar();

            Date startDate = new Date(); // time from which certificate is valid
            calendar.setTime(startDate);
            calendar.add(Calendar.MONTH, 12);
            Date expiryDate = calendar.getTime(); // time after which certificate is not valid

            BigInteger serialNumber = new BigInteger("1"); // serial number for certificate

            X500Name subjectName = new X500Name("CN=" + subject + ", C=DE");
            X500Name issuerName = new X500Name("CN=" + issuer + ", C=DE");

            HybridCertificateBuilder certificateBuilder = new HybridCertificateBuilder(
                    issuerName,
                    serialNumber,
                    startDate,
                    expiryDate,
                    subjectName,
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(primary.getPublic()),
                    secondary.getPublic()
            );
            certificateBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), false, new BasicConstraints(true));

            ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primarySigner);
            MessageSigner sigSecondary = new QTESLASigner();
            sigSecondary.init(true, secondarySigner);

            X509CertificateHolder x509CertificateHolder = certificateBuilder.buildHybrid(sigPrimary, sigSecondary, QTESLAUtils.getSignatureSize(QTESLASecurityCategory.HEURISTIC_III_SPEED), new AlgorithmIdentifier(new ASN1ObjectIdentifier(QTESLAUtils.OID_HEURISTIC_III_SPEED)));
            X509Certificate cert =  new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
            return cert;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
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

    private static void saveCertificateAsPEM(X509Certificate cert, String certName) {
        saveToFile(certName + ".crt", toPEM(cert));
    }


}
