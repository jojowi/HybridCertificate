package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.jcajce.provider.asymmetric.x509.VerifyHelper;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.List;

public class HybridValidation {
    private SubjectPublicKeyInfo hybridPublicKey;

    void validate(CertPath certPath) throws CertPathValidatorException {
        List<? extends Certificate> certificates = certPath.getCertificates();
        for(int j = certificates.size() - 1; j >= 0; --j) {
            validateCert(certificates.get(j));
        }
    }

    private void validateCert(Certificate certificate) throws CertPathValidatorException {
        X509Certificate cert = (X509Certificate) certificate;
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
            throw new CertPathValidatorException("Unable to validate signature");
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
}
