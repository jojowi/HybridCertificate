package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class QTESLAContentSigner implements ContentSigner {

    private AlgorithmIdentifier algId;
    private ByteArrayOutputStream stream;
    private QTESLASigner signer;

    public QTESLAContentSigner(QTESLAPrivateKeyParameters privateKey) {
        algId = QTESLAUtils.getAlgorithmIdentifier(privateKey.getSecurityCategory());
        this.signer = new QTESLASigner();
        this.signer.init(true, privateKey);
        this.stream = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
    }

    @Override
    public OutputStream getOutputStream() {
        return stream;
    }

    @Override
    public byte[] getSignature() {
        return signer.generateSignature(stream.toByteArray());
    }
}
