package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;

public class HybridSignature extends ASN1Object {

    public static final String OID = "2.5.29.56";
    private byte[] signature;

    public HybridSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(signature);
    }

    public byte[] getSignature() {
        return signature;
    }
}
