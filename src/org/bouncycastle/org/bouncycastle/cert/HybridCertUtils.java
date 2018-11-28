package org.bouncycastle.org.bouncycastle.cert;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.TBSCertificate;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class HybridCertUtils {

    public static byte[] extractBaseCert(X509Certificate cert) throws IOException {
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
                    DERTaggedObject newTagged = new DERTaggedObject(true, 3, new DERSequence(newextensions));
                    newTbs.add(newTagged);
                } else {
                    newTbs.add(tagged);
                }
            } else {
                newTbs.add(a);
            }
        }
        TBSCertificate base = TBSCertificate.getInstance(new DERSequence(newTbs));
        return base.getEncoded();
        /*HybridCertificateBuilder builder = new HybridCertificateBuilder(
                X500Name.getInstance(cert.getIssuerX500Principal().getEncoded()),
                cert.getSerialNumber(),
                cert.getNotBefore(),
                cert.getNotAfter(),
                X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()),
                SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded()),
                HybridKey.fromCert(cert).getKey());
        for (String oid : cert.getCriticalExtensionOIDs()) {
            builder.addExtension(new ASN1ObjectIdentifier(oid), true, cert.getExtensionValue(oid));
        }
        for (String oid : cert.getNonCriticalExtensionOIDs()) {
            if (!oid.equals(HybridKey.OID) && !oid.equals(HybridSignature.OID))
                builder.addExtension(new ASN1ObjectIdentifier(oid), false, cert.getExtensionValue(oid));
        }
        return builder.getBaseCert();*/
    }
}
