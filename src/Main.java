import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;

import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtils.createRSAKeyPair;
import static org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtils.readRSAKeyPair;
import static org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils.createQTESLAKeyPair;
import static org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils.readQTESLAKeyPair;

public class Main {
    public static void main(String[]args) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException {


//        AsymmetricCipherKeyPair CA1sec = createQTESLAKeyPair("CA1");
//        AsymmetricCipherKeyPair CA2sec = createQTESLAKeyPair("CA2");
//        AsymmetricCipherKeyPair EEsec = createQTESLAKeyPair("EE");
//        AsymmetricCipherKeyPair CA1 = createRSAKeyPair("CA1");
//        AsymmetricCipherKeyPair CA2 = createRSAKeyPair("CA2");
//        AsymmetricCipherKeyPair EE = createRSAKeyPair("EE");
//
        AsymmetricCipherKeyPair primary = readRSAKeyPair("EE");
        AsymmetricCipherKeyPair primarySigner = readRSAKeyPair("CA2");
        AsymmetricCipherKeyPair secondary = readQTESLAKeyPair("EE");
        AsymmetricCipherKeyPair secondarySigner = readQTESLAKeyPair("CA2");
//
        X509Certificate cert = createCertificate("EE", "CA2", primary, secondary, primarySigner.getPrivate(), secondarySigner.getPrivate());
        saveCertificateAsPEM(cert, "CA2-EE");

        X509Certificate ca1 = readCertificate("CA1");
        X509Certificate ca2 = readCertificate("CA1-CA2");
        X509Certificate ee = readCertificate("CA2-EE");

        QTESLASigner verify = new QTESLASigner();
        verify.init(false, HybridKey.fromCert(ca2).getKey());
        byte[] base = extractBaseCert(ee);
        System.out.println(Arrays.toString(base));
        System.out.println(verify.verifySignature(base, HybridSignature.fromCert(ee).getSignature()));
    }

    private static byte[] extractBaseCert(X509Certificate cert) throws IOException {
        ASN1Sequence tbs = null;
        ASN1EncodableVector newTbs = new ASN1EncodableVector();
        try {
            tbs = (ASN1Sequence) ASN1Sequence.fromByteArray(cert.getTBSCertificate());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        for (ASN1Encodable a : tbs.toArray()) {
            if (a instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) a;
                if (tagged.isExplicit() && tagged.getTagNo() == 3) {
                    ASN1Sequence extensions = (ASN1Sequence) tagged.getObject();
                    ASN1EncodableVector newextensions = new ASN1EncodableVector();
                    for (ASN1Encodable b : extensions.toArray()) {
                        ASN1Sequence extension = (ASN1Sequence) b;
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extension.getObjectAt(0);

                        if (!oid.getId().equals(HybridSignature.OID)) {
                            newextensions.add(extension);
                        }
                    }
                    DERTaggedObject newTagged = new DERTaggedObject(true, 3, new DERSequence(newextensions));
                    newTbs.add(newTagged);
                } else {
                    newTbs.add(tagged);
                }
            } else {
                newTbs.add(a);
            }
        }
        TBSCertificate base = TBSCertificate.getInstance(new DERSequence(newTbs));
        return base.getEncoded();
        /*HybridCertificateBuilder builder = new HybridCertificateBuilder(
                X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
                cert.getSerialNumber(),
                cert.getNotBefore(),
                cert.getNotAfter(),
                X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()),
                SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded()),
                HybridKey.fromCert(cert).getKey());
        for (String oid : cert.getCriticalExtensionOIDs()) {
            builder.addExtension(new ASN1ObjectIdentifier(oid), true, cert.getExtensionValue(oid));
        }
        for (String oid : cert.getNonCriticalExtensionOIDs()) {
            if (!oid.equals(HybridKey.OID) && !oid.equals(HybridSignature.OID))
                builder.addExtension(new ASN1ObjectIdentifier(oid), false, cert.getExtensionValue(oid));
        }
        return builder.getBaseCert();*/
    }

    private static X509Certificate readCertificate(String name) {
        try {
            FileInputStream fis = new FileInputStream(name + ".crt");
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate c = cf.generateCertificate(bis);
            bis.close();
            fis.close();
            X509Certificate cert = (X509Certificate) c;
            return  cert;
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

            ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primarySigner);
            MessageSigner sigSecondary = new QTESLASigner();
            sigSecondary.init(true, secondarySigner);

            X509CertificateHolder x509CertificateHolder = certificateBuilder.buildHybrid(sigPrimary, sigSecondary);
            X509Certificate cert =  new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
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


}
