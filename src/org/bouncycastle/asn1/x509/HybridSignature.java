package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class HybridSignature extends ASN1Object {

    public static final String OID = "2.5.29.56";
    private byte[] signature;
    private int length;

    public HybridSignature(byte[] signature, int length) {
        this.signature = signature;
        this.length = length;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(length));
        v.add(new DERBitString(signature));
        return new DERSequence(v);
    }

    public byte[] getSignature() {
        //System.out.println(Arrays.toString(signature));
        return signature;
    }

    public int getLength() {
        return length;
    }

    public static HybridSignature fromCert(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(OID);
        ASN1InputStream input = new ASN1InputStream(data);
        ASN1OctetString octstr = ASN1OctetString.getInstance(input.readObject());
        ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(octstr.getOctets());
        ASN1BitString sig = (ASN1BitString) seq.getObjectAt(1);
        ASN1Integer length = (ASN1Integer) seq.getObjectAt(0);
        return new HybridSignature(sig.getOctets(), length.getValue().intValue());
    }
}
