package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.OutputStream;

public class NullContentSigner implements ContentSigner {
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.30"));
    }

    @Override
    public OutputStream getOutputStream() {
        return new OutputStream() {
            @Override
            public void write(int b) {

            }
        };
    }

    @Override
    public byte[] getSignature() {
        return new byte[0];
    }
}
