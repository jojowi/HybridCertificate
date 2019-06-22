package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;

/**
 * Helper functions for qTESLA(-keys)
 */
public class QTESLAUtils {

    /**
     * OIDs for different modes of qTESLA
     */
    private static final String OID_HEURISTIC_I = "1.3.6.1.4.1.311.89.2.2.1";
    private static final String OID_HEURISTIC_III_SIZE = "1.3.6.1.4.1.311.89.2.2.2";
    private static final String OID_HEURISTIC_III_SPEED = "1.3.6.1.4.1.311.89.2.2.3";
    private static final String OID_PROVABLY_SECURE_I = "1.3.6.1.4.1.311.89.2.2.4";
    private static final String OID_PROVABLY_SECURE_III = "1.3.6.1.4.1.311.89.2.2.5";



    /**
     * Extract a qTESLA public key from a SubjectPublicKeyInfo object
     *
     * @param key the SubjectPublicKeyInfo
     * @return the public key
     */
    public static QTESLAPublicKeyParameters fromSubjectPublicKeyInfo(SubjectPublicKeyInfo key) {
        byte[] data = key.getPublicKeyData().getOctets();
        return new QTESLAPublicKeyParameters(getSecurityCategory(key.getAlgorithm()), data);
    }

    public static SubjectPublicKeyInfo toSubjectPublicKeyInfo(QTESLAPublicKeyParameters publicKey) {
        AlgorithmIdentifier algId = QTESLAUtils.getAlgorithmIdentifier(publicKey.getSecurityCategory());
        return new SubjectPublicKeyInfo(algId, publicKey.getPublicData());
    }

    /**
     * Check if the given AlgID is qTESLA
     *
     * @param algId the algorithm identifier
     * @return true if the AlgID belongs to qTESLA, false otherwise
     */
    public static boolean isQTESLA(AlgorithmIdentifier algId) {
        String oid = algId.getAlgorithm().getId();
        return oid.equals(OID_HEURISTIC_I) || oid.equals(OID_HEURISTIC_III_SIZE) || oid.equals(OID_HEURISTIC_III_SPEED);
    }

    /**
     * Get the qTESLA security category from a (qTESLA) AlgID
     *
     * @param algId the algorithm identifier
     * @return the security category
     */
    public static int getSecurityCategory(AlgorithmIdentifier algId) {
        switch (algId.getAlgorithm().getId()) {
            case OID_HEURISTIC_I:
                return QTESLASecurityCategory.HEURISTIC_I;
            case OID_HEURISTIC_III_SIZE:
                return QTESLASecurityCategory.HEURISTIC_III_SIZE;
            case OID_HEURISTIC_III_SPEED:
                return QTESLASecurityCategory.HEURISTIC_III_SPEED;
            case OID_PROVABLY_SECURE_I:
                return QTESLASecurityCategory.PROVABLY_SECURE_I;
            case OID_PROVABLY_SECURE_III:
                return QTESLASecurityCategory.PROVABLY_SECURE_III;
            default:
                return -1;
        }
    }

    /**
     * Get the algorithm identifier for a qTESLA security category
     *
     * @param securityCategory the security category
     * @return the OID of the algorithm identifier as string
     */
    private static String getOID(int securityCategory) {
        switch (securityCategory) {
            case QTESLASecurityCategory.HEURISTIC_I:
                return OID_HEURISTIC_I;
            case QTESLASecurityCategory.HEURISTIC_III_SIZE:
                return OID_HEURISTIC_III_SIZE;
            case QTESLASecurityCategory.HEURISTIC_III_SPEED:
                return OID_HEURISTIC_III_SPEED;
            case QTESLASecurityCategory.PROVABLY_SECURE_I:
                return OID_PROVABLY_SECURE_I;
            case QTESLASecurityCategory.PROVABLY_SECURE_III:
                return OID_PROVABLY_SECURE_III;
            default:
                return "";
        }
    }

    /**
     * Get the algorithm identifier for a qTESLA security category
     *
     * @param securityCategory the security category
     * @return the algorithm identifier
     */
    public static AlgorithmIdentifier getAlgorithmIdentifier(int securityCategory) {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(getOID(securityCategory)));
    }

    /**
     * Encode a qTESLA public key to asn1
     *
     * @param key the qTESLA public key
     * @return the key as asn1 primitive
     */
    public static ASN1Primitive toASN1Primitive(QTESLAPublicKeyParameters key) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(getAlgorithmIdentifier(key.getSecurityCategory()));
        v.add(new DERBitString(key.getPublicData()));
        return new DERSequence(v);
    }

    /**
     * Encode a qTESLA private key to asn1
     *
     * @param key the qTESLA private key
     * @return the key as asn1 primitive
     */
    public static ASN1Primitive toASN1Primitive(QTESLAPrivateKeyParameters key) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(getAlgorithmIdentifier(key.getSecurityCategory()));
        v.add(new DERBitString(key.getSecret()));
        return new DERSequence(v);
    }

    /**
     * Decode a qTESLA public key from asn1
     *
     * @param data the byte data (asn1) of the key
     * @return the public key
     */
    public static QTESLAPublicKeyParameters fromASN1Primitive(byte[] data) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(data);
        AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        ASN1BitString key = (ASN1BitString) seq.getObjectAt(1);
        return new QTESLAPublicKeyParameters(getSecurityCategory(algorithmIdentifier), key.getOctets());
    }

    /**
     * Decode a qTESLA private key from asn1
     *
     * @param data the byte data of the key
     * @return the private key
     */
    public static QTESLAPrivateKeyParameters fromASN1PrimitivePrivate(byte[] data) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(data);
        AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        ASN1BitString key = (ASN1BitString) seq.getObjectAt(1);
        return new QTESLAPrivateKeyParameters(getSecurityCategory(algorithmIdentifier), key.getOctets());
    }

}
