package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;

public class HybridCSRBuilder {

    private AsymmetricKeyParameter secondary;
    private PKCS10CertificationRequestBuilder builder;
    private ExtensionsGenerator extGen;

    public HybridCSRBuilder(X500Name subject, SubjectPublicKeyInfo publicKeyInfo, AsymmetricKeyParameter secondary) {
        this.builder = new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);
        this.secondary = secondary;
        extGen = new ExtensionsGenerator();
    }

    public HybridCSRBuilder(X500Name subject, PublicKey primary, AsymmetricKeyParameter secondary) {
        this(subject, SubjectPublicKeyInfo.getInstance(primary.getEncoded()), secondary);
    }

    public HybridCSRBuilder(X500Principal subject, PublicKey primary, AsymmetricKeyParameter secondary) {
        this(X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(primary.getEncoded()), secondary);
    }

    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value) throws IOException {
        this.extGen.addExtension(oid, isCritical, value);
    }

    public void addExtension(Extension extension) {
        this.extGen.addExtension(extension);
    }

    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, byte[] encodedValue) {
        this.extGen.addExtension(oid, isCritical, encodedValue);
    }

    private CertificationRequestInfo prepareForHybrid(ContentSigner primary, int secondarySigSize, AlgorithmIdentifier secondaryAlgId) {
        try {
            addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
            byte[] zeros = new byte[secondarySigSize];
            addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(zeros, secondaryAlgId));
        } catch (IOException e) {
            e.printStackTrace();
        }
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        PKCS10CertificationRequest csr = builder.build(primary);
        return csr.toASN1Structure().getCertificationRequestInfo();
    }

    public PKCS10CertificationRequest buildHybrid(ContentSigner primary, ContentSigner secondary) {
        int secondarySigSize = secondary.getSignature().length;
        CertificationRequestInfo tbs = prepareForHybrid(primary, secondarySigSize, secondary.getAlgorithmIdentifier());
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
        CertificationRequestInfo info = CertificationRequestInfo.getInstance(bytes);
        OutputStream sOut = primary.getOutputStream();
        try {
            sOut.write(info.getEncoded("DER"));
            sOut.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new PKCS10CertificationRequest(new CertificationRequest(info, primary.getAlgorithmIdentifier(), new DERBitString(primary.getSignature())));
    }
}
