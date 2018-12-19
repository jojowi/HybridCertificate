package org.bouncycastle.jcajce.provider.asymmetric.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

import java.security.*;

public class VerifyHelper {

    public static Signature createSignature(AlgorithmIdentifier algId) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String sigName = X509SignatureUtil.getSignatureName(algId);
        JcaJceHelper bcHelper = new BCJcaJceHelper();
        Signature signature;
        try {
            signature = bcHelper.createSignature(sigName);
        } catch (Exception var5) {
            signature = Signature.getInstance(sigName);
        }
        ASN1Encodable params = algId.getParameters();
        X509SignatureUtil.setSignatureParameters(signature, params);
        return signature;
    }
}
