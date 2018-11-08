package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class QTESLAUtils {

    public static ASN1Primitive toASN1Primitive(QTESLAPublicKeyParameters key) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERBitString(key.getPublicData()));
        v.add(new ASN1Integer(key.getSecurityCategory()));
        return new DERSequence(v);
    }

    public static ASN1Primitive toASN1Primitive(QTESLAPrivateKeyParameters key) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERBitString(key.getSecret()));
        v.add(new ASN1Integer(key.getSecurityCategory()));
        return new DERSequence(v);
    }

    public static QTESLAPublicKeyParameters fromASN1Primitive(byte[] data) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(data);
        DERBitString der = (DERBitString) seq.getObjectAt(0);
        ASN1Integer sec = (ASN1Integer) seq.getObjectAt(1);
        return new QTESLAPublicKeyParameters(sec.getValue().intValue(), der.getBytes());
    }

    public static QTESLAPrivateKeyParameters fromASN1PrimitivePrivate(byte[] data) throws IOException {
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(data);
        DERBitString der = (DERBitString) seq.getObjectAt(0);
        ASN1Integer sec = (ASN1Integer) seq.getObjectAt(1);
        return new QTESLAPrivateKeyParameters(sec.getValue().intValue(), der.getBytes());
    }

    public static AsymmetricCipherKeyPair createQTESLAKeyPair(String name) {
        QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
        try {
            gen.init(new QTESLAKeyGenerationParameters(4, SecureRandom.getInstanceStrong()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        try {
            File file = new File(name + "_public.key");
            FileOutputStream out = new FileOutputStream(file);
            out.write(QTESLAUtils.toASN1Primitive((QTESLAPublicKeyParameters) pair.getPublic()).getEncoded());
            out.close();
            file = new File(name + "_private.key");
            out = new FileOutputStream(file);
            out.write(QTESLAUtils.toASN1Primitive((QTESLAPrivateKeyParameters) pair.getPrivate()).getEncoded());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pair;
    }

    public static AsymmetricCipherKeyPair readQTESLAKeyPair(String name) {
        try {
            File file = new File(name + "_public.key");
            FileInputStream in = new FileInputStream(file);
            QTESLAPublicKeyParameters pub = QTESLAUtils.fromASN1Primitive(in.readAllBytes());
            in.close();
            file = new File(name + "_private.key");
            in = new FileInputStream(file);
            QTESLAPrivateKeyParameters priv = QTESLAUtils.fromASN1PrimitivePrivate(in.readAllBytes());
            in.close();
            return new AsymmetricCipherKeyPair(pub, priv);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
