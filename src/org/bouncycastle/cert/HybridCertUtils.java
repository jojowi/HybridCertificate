package org.bouncycastle.cert;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.TBSCertificate;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class HybridCertUtils {

    @Deprecated
    public static byte[] extractBaseCert(X509Certificate cert) throws IOException, CertificateEncodingException {
        byte[] base = cert.getTBSCertificate();
        Arrays.fill(base, base.length - HybridSignature.fromCert(cert).getSignature().length, base.length, (byte) 0);
        for(byte c : base) {
            System.out.format("%h ", c);
        }
        System.out.println();
        return base;
    }

    /**
     * Extract the "base cert" from a hybrid certificate (the part over which the secondary signature was built)
     *
     * @param cert
     * @return
     */
    public static byte[] extractBaseCertSearch(X509Certificate cert) throws IOException, CertificateEncodingException {
        long start = System.nanoTime();
        byte[] base = cert.getTBSCertificate();
        byte[] signature = HybridSignature.fromCert(cert).getSignature();
        List<Byte> baseList = new LinkedList<>();
        for (byte b : base) {
            baseList.add(b);
        }
        List<Byte> sigList = new LinkedList<>();
        for (byte b : signature) {
            sigList.add(b);
        }
        int index = Collections.indexOfSubList(baseList, sigList);
        Arrays.fill(base, index, index + signature.length, (byte) 0);
        long end = System.nanoTime();
        long diff = end - start;
        System.out.println("Time: " + (diff / 1000000f));
        System.out.println(Arrays.toString(base));
        return base;
    }

    @Deprecated
    public static byte[] extractBaseCertRebuild(X509Certificate cert) throws IOException {
        ASN1Sequence tbs = null;
        ASN1EncodableVector newTbs = new ASN1EncodableVector();
        try {
            tbs = (ASN1Sequence) ASN1Sequence.fromByteArray(cert.getTBSCertificate());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        for (ASN1Encodable a : tbs.toArray()) {
            if (a instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) a;
                if (tagged.isExplicit() && tagged.getTagNo() == 3) {
                    ASN1Sequence extensions = (ASN1Sequence) tagged.getObject();
                    ASN1EncodableVector newextensions = new ASN1EncodableVector();
                    for (ASN1Encodable b : extensions.toArray()) {
                        ASN1Sequence extension = (ASN1Sequence) b;
                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extension.getObjectAt(0);

                        if (!oid.getId().equals(HybridSignature.OID)) {
                            newextensions.add(extension);
                        }
                    }
                    ASN1Sequence seq = null;
                    try {
                        seq = extensions.getClass().getConstructor(ASN1EncodableVector.class).newInstance(newextensions);
                    } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
                        e.printStackTrace();
                    }
                    ASN1TaggedObject newTagged = null;
                    try {
                        newTagged = tagged.getClass().getConstructor(boolean.class, int.class, ASN1Encodable.class).newInstance(true, 3, seq);
                    } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
                        e.printStackTrace();
                    }
                    newTbs.add(newTagged);
                } else {
                    newTbs.add(tagged);
                }
            } else {
                newTbs.add(a);
            }
        }
        TBSCertificate base = null;
        try {
            base = TBSCertificate.getInstance(tbs.getClass().getConstructor(ASN1EncodableVector.class).newInstance(newTbs));
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            e.printStackTrace();
        }
        return base.getEncoded();
    }
}
