package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;
import org.bouncycastle.pqc.jcajce.provider.QTESLA;

import java.io.IOException;
import java.util.Arrays;

import static org.bouncycastle.utils.ByteArrayUtils.replaceZeros;

public class HybridCSRUtils {
    public static byte[] extractBaseCSRSearch(PKCS10CertificationRequest csr) throws IOException {
        byte[] base = csr.toASN1Structure().getCertificationRequestInfo().getEncoded();
        byte[] signature = HybridSignature.fromCSR(csr).getSignature();
        replaceZeros(base, signature);
        //System.out.println(Arrays.toString(base));
        return base;
    }
}
