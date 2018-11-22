package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pqc.crypto.MessageSigner;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

public class HybridCertificateBuilder extends X509v3CertificateBuilder {

    private AsymmetricKeyParameter secondary;

    public HybridCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo primary, AsymmetricKeyParameter secondary) {
        super(issuer, serial, notBefore, notAfter, subject, primary);
        this.secondary = secondary;
    }

    public X509CertificateHolder buildHybrid(ContentSigner primary, ContentSigner secondary) {
        try {
            addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
        } catch (CertIOException e) {
            e.printStackTrace();
        }
        X509CertificateHolder cert = build(primary);
        TBSCertificate tbs = cert.toASN1Structure().getTBSCertificate();
        try {
            byte[] signature = generateSig(secondary, tbs);
            addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(signature));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return build(primary);
    }

    private static byte[] generateSig(ContentSigner signer, ASN1Encodable tbsCert) throws IOException {
        OutputStream out = signer.getOutputStream();
        DEROutputStream derOut = new DEROutputStream(out);
        derOut.writeObject(tbsCert);
        out.close();
        return signer.getSignature();
    }

    public byte[] getBaseCert() throws IOException {
        try {
            addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
        } catch (CertIOException e) {
            e.printStackTrace();
        }
        X509CertificateHolder cert = build(new NullContentSigner());
        TBSCertificate tbs = cert.toASN1Structure().getTBSCertificate();
        //System.out.println(Arrays.toString(tbs.toASN1Primitive().getEncoded()));
        return tbs.toASN1Primitive().getEncoded();
    }

    public X509CertificateHolder buildHybrid(ContentSigner primary, MessageSigner secondary) {
        try {
            addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
        } catch (CertIOException e) {
            e.printStackTrace();
        }
        X509CertificateHolder cert = build(primary);
        TBSCertificate tbs = cert.toASN1Structure().getTBSCertificate();
        try {
            System.out.println(Arrays.toString(tbs.toASN1Primitive().getEncoded()));
            byte[] signature = secondary.generateSignature(tbs.toASN1Primitive().getEncoded());
            //System.out.println(Arrays.toString(signature));
            addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(signature));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return build(primary);
    }
}
