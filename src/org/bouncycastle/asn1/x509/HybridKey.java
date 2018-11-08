package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class HybridKey extends ASN1Object {

    public static final String OID = "2.5.29.55";
    private SubjectPublicKeyInfo key;

    public HybridKey(AsymmetricKeyParameter key) {
        try {
            this.key = createSubjectPublicKeyInfo(key);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private HybridKey(SubjectPublicKeyInfo key) {
        this.key = key;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(key);
    }

    public AsymmetricKeyParameter getKey() {
        try {
            switch (key.getAlgorithm().getAlgorithm().getId()) {
                case "1.2.840.113549.1.1.12":
                    byte[] data = key.getPublicKeyData().getEncoded();
                    ASN1BitString asn1 = (ASN1BitString) ASN1BitString.fromByteArray(data);
                    return QTESLAUtils.fromASN1Primitive(asn1.getBytes());
                default:
                    throw new IllegalArgumentException("key parameters not recognised.");
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        if (publicKey instanceof QTESLAPublicKeyParameters) {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.12")), QTESLAUtils.toASN1Primitive((QTESLAPublicKeyParameters) publicKey));
        } else
        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
    }

    public static HybridKey fromCert(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(OID);
        ASN1InputStream input = new ASN1InputStream(data);
        ASN1OctetString octstr = ASN1OctetString.getInstance(input.readObject());
        ASN1Sequence asn2 = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(octstr.getOctets()));
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn2.getObjectAt(0));
        return new HybridKey(subjectPublicKeyInfo);
    }
}
