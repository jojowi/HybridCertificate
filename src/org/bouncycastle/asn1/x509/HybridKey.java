package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.X509AttrCertParser;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class HybridKey extends ASN1Object {

    public static final String OID = "2.5.29.55";
    private SubjectPublicKeyInfo key;

    public HybridKey(AsymmetricKeyParameter key) {
        try {
            this.key = createSubjectPublicKeyInfo(key);
            System.out.println(this.key.getPublicKeyData());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(key);
    }

    public SubjectPublicKeyInfo getKey() {
        return key;
    }

    private static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        if (publicKey instanceof QTESLAPublicKeyParameters) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            QTESLAPublicKeyParameters key = (QTESLAPublicKeyParameters) publicKey;
            v.add(new DERBitString(key.getPublicData()));
            //v.add(new ASN1Integer(key.getSecurityCategory()));
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.12")), new DERSequence(v));
        } else
        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
    }

    public static void fromCert(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(OID);
        ASN1InputStream input = new ASN1InputStream(data);

        ASN1Primitive p;
        while ((p = input.readObject()) != null) {
            ASN1OctetString octstr = ASN1OctetString.getInstance(p);
            ASN1Sequence asn2 = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(octstr.getOctets()));
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(asn2.getObjectAt(0));
            System.out.println(subjectPublicKeyInfo.getPublicKeyData());
        }
    }
}
