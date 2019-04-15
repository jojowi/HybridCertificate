package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Helper class for creating hybrid certificates
 */
public class HybridCertificateBuilder extends X509v3CertificateBuilder {
    private AsymmetricKeyParameter secondary;

    /**
     * Create a builder for a hybrid version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param primary the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo primary, AsymmetricKeyParameter secondary) {
        super(issuer, serial, notBefore, notAfter, subject, primary);
        this.secondary = secondary;
    }

    /**
     * Create a builder for a hybrid version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), secondary);
    }

    /**
     * Create a builder for a hybrid version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridCertificateBuilder(X500Principal issuer, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(X500Name.getInstance(issuer.getEncoded()), serial, notBefore, notAfter, X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), secondary);
    }

    /**
     * Create a builder for a hybrid version 3 certificate.
     *
     * @param issuerCert the certificate of the issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridCertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(issuerCert.getSubjectX500Principal(), serial, notBefore, notAfter, subject, publicKey, secondary);
    }

    /**
     * Create a builder for a hybrid version 3 certificate.
     *
     * @param issuerCert the certificate of the issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridCertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()), serial, notBefore, notAfter, subject, publicKey, secondary);
    }

    /*public X509CertificateHolder buildHybrid(ContentSigner primary, ContentSigner secondary, int secondarySigSize) {
        TBSCertificate tbs = prepareForHybrid(primary, secondarySigSize, secondary.getAlgorithmIdentifier());
        try {
            byte[] signature = generateSig(secondary, tbs);
            addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(signature, secondarySigSize, secondary.getAlgorithmIdentifier()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return build(primary);
    }*/

    /*
    private static byte[] generateSig(ContentSigner signer, ASN1Encodable tbsCert) throws IOException {
        OutputStream out = signer.getOutputStream();
        DEROutputStream derOut = new DEROutputStream(out);
        derOut.writeObject(tbsCert);
        out.close();
        return signer.getSignature();
    }*/

    private TBSCertificate prepareForHybrid(ContentSigner primary, int secondarySigSize, AlgorithmIdentifier secondaryAlgId) {
        try {
            addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
            byte[] zeros = new byte[secondarySigSize];
            addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(zeros, secondaryAlgId));
        } catch (CertIOException e) {
            e.printStackTrace();
        }
        X509CertificateHolder cert = build(primary);
        return cert.toASN1Structure().getTBSCertificate();
    }

    /**
     * Generate a hybrid X.509 certificate, based on the current issuer and subject using the passed in signer.
     *
     * @param primary the content signer to be used to generate the signature validating the certificate
     * @param secondary the message signer to be used to generate the secondary (hybrid) signature
     * @return a holder containing the resulting signed hybrid certificate
     */
    public X509CertificateHolder buildHybrid(ContentSigner primary, ContentSigner secondary) {
        int secondarySigSize = secondary.getSignature().length;
        TBSCertificate tbs = prepareForHybrid(primary, secondarySigSize, secondary.getAlgorithmIdentifier());
        byte[] bytes = null;
        try {
            secondary.getOutputStream().write(tbs.toASN1Primitive().getEncoded());
            byte[] signature = secondary.getSignature();
            bytes = tbs.getEncoded();
            System.arraycopy(signature, 0, bytes, bytes.length - secondarySigSize, secondarySigSize);
            //addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(signature));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return CertUtils.generateFullCert(primary, TBSCertificate.getInstance(bytes));
    }

    @Override
    public X509CertificateHolder build(ContentSigner primary) {
        throw new UnsupportedOperationException();
    }
}
