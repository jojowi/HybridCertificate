import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.qtesla.*;

public class Main {
    public static void main(String[]args) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {


        QTESLAKeyPairGenerator genSecondary = new QTESLAKeyPairGenerator();
        genSecondary.init(new QTESLAKeyGenerationParameters(4, SecureRandom.getInstanceStrong()));
        AsymmetricCipherKeyPair secondary = genSecondary.generateKeyPair();
        AsymmetricCipherKeyPair secondarySigner = genSecondary.generateKeyPair();

        RSAKeyPairGenerator genPrimary = new RSAKeyPairGenerator();
        genPrimary.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 1024, 25));
        AsymmetricCipherKeyPair primary = genPrimary.generateKeyPair();
        AsymmetricCipherKeyPair primarySigner = genPrimary.generateKeyPair();
        X509Certificate cert = createCertificate(primary, secondary, primarySigner.getPrivate(), secondarySigner.getPrivate());
        System.out.println(Arrays.toString(((QTESLAPublicKeyParameters)secondary.getPublic()).getPublicData()));

        HybridCertificateBuilder builder = new HybridCertificateBuilder(
                X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
                cert.getSerialNumber(),
                cert.getNotBefore(),
                cert.getNotAfter(),
                X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()),
                SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded()),
                secondary.getPublic());
        HybridKey.fromCert(cert);
        System.out.println(Arrays.toString(cert.getExtensionValue(HybridKey.OID)));
        for (String oid : cert.getCriticalExtensionOIDs()) {
            builder.addExtension(new ASN1ObjectIdentifier(oid), true, cert.getExtensionValue(oid));
        }
        for (String oid : cert.getNonCriticalExtensionOIDs()) {
            if (!oid.equals(HybridKey.OID) && !oid.equals(HybridSignature.OID))
                builder.addExtension(new ASN1ObjectIdentifier(oid), false, cert.getExtensionValue(oid));
        }
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withRSA");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);
        ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primarySigner.getPrivate());
        MessageSigner sigSecondary = new QTESLASigner();
        sigSecondary.init(true, secondarySigner.getPrivate());

        X509CertificateHolder x509CertificateHolder = builder.buildHybrid(sigPrimary, sigSecondary);
        X509Certificate c =  new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
        saveCertificateAsPEM(c, "Hybrid2");
        //readCertificate();
    }

    private static void readCertificate() {
        try {
            FileInputStream fis = new FileInputStream("Hybrid.crt");
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate c = cf.generateCertificate(bis);
            bis.close();
            fis.close();
            X509Certificate cert = (X509Certificate) c;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate createCertificate(AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair secondary, AsymmetricKeyParameter primarySigner, AsymmetricKeyParameter secondarySigner) {
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

            X500Name subjectName = new X500Name("CN=HybridKey, C=DE");

            HybridCertificateBuilder certificateBuilder = new HybridCertificateBuilder(
                    subjectName,
                    serialNumber,
                    startDate,
                    expiryDate,
                    subjectName,
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(primary.getPublic()),
                    secondary.getPublic()
            );

            ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primarySigner);
            MessageSigner sigSecondary = new QTESLASigner();
            sigSecondary.init(true, secondarySigner);

            X509CertificateHolder x509CertificateHolder = certificateBuilder.buildHybrid(sigPrimary, sigSecondary);
            X509Certificate cert =  new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
            saveCertificateAsPEM(cert, "Hybrid");
            return cert;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void saveToFile(String filename, String content) {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(new File(filename)));
            writer.write(content);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String toPEM(Object obj) {
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

    public static void saveCertificateAsPEM(X509Certificate cert, String certName) {
        saveToFile(certName + ".crt", toPEM(cert));
    }

    public static void saveKeyAsPem(String Filename, AsymmetricKeyParameter key) {
        saveToFile(Filename + ".pem", toPEM(key));
    }
}
