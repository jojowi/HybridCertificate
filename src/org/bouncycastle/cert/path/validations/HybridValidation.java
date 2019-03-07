package org.bouncycastle.cert.path.validations;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.jcajce.provider.asymmetric.x509.VerifyHelper;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;
import org.bouncycastle.util.Memoable;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class HybridValidation implements CertPathValidation {
    private SubjectPublicKeyInfo hybridPublicKey;

    @Override
    public void validate(CertPathValidationContext certPathValidationContext, X509CertificateHolder x509CertificateHolder) throws CertPathValidationException {
        X509Certificate cert = null;
        try {
            cert = new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        if (this.hybridPublicKey == null) {
            try {
                this.hybridPublicKey = HybridKey.fromCert(cert).getKey();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        boolean verify = false;
        AlgorithmIdentifier algId = getAlgId(cert);
        if (QTESLAUtils.isQTESLA(algId)) {
            QTESLASigner signer = new QTESLASigner();
            signer.init(false, QTESLAUtils.fromSubjectPublicKeyInfo(hybridPublicKey));
            try {
                verify = signer.verifySignature(HybridCertUtils.extractBaseCertSearch(cert), HybridSignature.fromCert(cert).getSignature());
            } catch (IOException | CertificateEncodingException e) {
                e.printStackTrace();
            }
        } else {
            try {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                Signature signature = VerifyHelper.createSignature(algId);
                signature.initVerify(converter.getPublicKey(hybridPublicKey));
                signature.update(HybridCertUtils.extractBaseCertSearch(cert));
                verify = signature.verify(HybridSignature.fromCert(cert).getSignature());
            } catch (NoSuchAlgorithmException | IOException | SignatureException | InvalidKeyException | CertificateEncodingException e) {
                e.printStackTrace();
            }
        }
        if (!verify) {
            throw new CertPathValidationException("Unable to validate signature");
        }

        try {
            this.hybridPublicKey = HybridKey.fromCert(cert).getKey();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private AlgorithmIdentifier getAlgId(X509Certificate cert) {
        try {
            return HybridSignature.fromCert(cert).getAlgorithmIdentifier();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Memoable copy() {
        HybridValidation val = new HybridValidation();
        val.hybridPublicKey = hybridPublicKey;
        return val;
    }

    @Override
    public void reset(Memoable memoable) {
        HybridValidation val = (HybridValidation) memoable;
        hybridPublicKey = val.hybridPublicKey;
    }
}
