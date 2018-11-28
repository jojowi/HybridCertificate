package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.asn1.*;

import java.io.*;

public class QTESLAUtils {

    public static ASN1Primitive toASN1Primitive(QTESLAPublicKeyParameters key) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERBitString(key.getPublicData()));
        v.add(new ASN1Integer(key.getSecurityCategory()));
        return new DERSequence(v);
    }

    public static ASN1Primitive toASN1Primitive(QTESLAPrivateKeyParameters key) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERBitString(key.getSecret()));
        v.add(new ASN1Integer(key.getSecurityCategory()));
        return new DERSequence(v);
    }

    public static QTESLAPublicKeyParameters fromASN1Primitive(byte[] data) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(data);
        DERBitString der = (DERBitString) seq.getObjectAt(0);
        ASN1Integer sec = (ASN1Integer) seq.getObjectAt(1);
        return new QTESLAPublicKeyParameters(sec.getValue().intValue(), der.getBytes());
    }

    public static QTESLAPrivateKeyParameters fromASN1PrimitivePrivate(byte[] data) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(data);
        DERBitString der = (DERBitString) seq.getObjectAt(0);
        ASN1Integer sec = (ASN1Integer) seq.getObjectAt(1);
        return new QTESLAPrivateKeyParameters(sec.getValue().intValue(), der.getBytes());
    }


}
