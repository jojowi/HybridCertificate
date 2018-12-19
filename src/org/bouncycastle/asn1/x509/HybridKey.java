package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class HybridKey extends ASN1Object {

    public static final String OID = "2.5.29.211";
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
        return key.toASN1Primitive();
    }

    public SubjectPublicKeyInfo getKey() {
        return key;
    }

    private static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        if (publicKey instanceof QTESLAPublicKeyParameters) {
            AlgorithmIdentifier algId = QTESLAUtils.getAlgorithmIdentifier(((QTESLAPublicKeyParameters) publicKey).getSecurityCategory());
            return new SubjectPublicKeyInfo(algId, ((QTESLAPublicKeyParameters) publicKey).getPublicData());
        } else
        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
    }

    public static HybridKey fromCert(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(OID);
        ASN1InputStream input = new ASN1InputStream(data);
        ASN1OctetString octstr = ASN1OctetString.getInstance(input.readObject());
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(octstr.getOctets());
        return new HybridKey(subjectPublicKeyInfo);
    }
}
