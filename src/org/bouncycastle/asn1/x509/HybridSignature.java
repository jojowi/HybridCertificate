package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

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
        System.out.println(Arrays.toString(signature));
        return signature;
    }

    public static HybridSignature fromCert(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(OID);
        ASN1InputStream input = new ASN1InputStream(data);

        ASN1OctetString octstr = ASN1OctetString.getInstance(input.readObject());
        ASN1OctetString inner = (ASN1OctetString) ASN1OctetString.fromByteArray(octstr.getOctets());
        return new HybridSignature(inner.getOctets());
    }
}
