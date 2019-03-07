package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pqc.crypto.MessageSigner;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;

public class HybridCertificateBuilder extends X509v3CertificateBuilder {

    private AsymmetricKeyParameter secondary;

    public HybridCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo primary, AsymmetricKeyParameter secondary) {
        super(issuer, serial, notBefore, notAfter, subject, primary);
        this.secondary = secondary;
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

    private static byte[] generateSig(ContentSigner signer, ASN1Encodable tbsCert) throws IOException {
        OutputStream out = signer.getOutputStream();
        DEROutputStream derOut = new DEROutputStream(out);
        derOut.writeObject(tbsCert);
        out.close();
        return signer.getSignature();
    }

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

    public X509CertificateHolder buildHybrid(ContentSigner primary, MessageSigner secondary, int secondarySigSize, AlgorithmIdentifier secondaryAlgId) {
        TBSCertificate tbs = prepareForHybrid(primary, secondarySigSize, secondaryAlgId);
        byte[] bytes = null;
        try {
            byte[] signature = secondary.generateSignature(tbs.toASN1Primitive().getEncoded());
            bytes = tbs.getEncoded();
            System.arraycopy(signature, 0, bytes, bytes.length - secondarySigSize, secondarySigSize);
            //addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(signature));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return CertUtils.generateFullCert(primary, TBSCertificate.getInstance(bytes));
    }
}
