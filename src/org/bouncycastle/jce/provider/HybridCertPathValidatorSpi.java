package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;

public class HybridCertPathValidatorSpi extends PKIXCertPathValidatorSpi {

    @Override
    public HybridCertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) super.engineValidate(certPath, params);

        HybridValidation hybridValidation = new HybridValidation();
        try {
            hybridValidation.validate(certPath);
        } catch (CertPathValidatorException exception) {
            return new HybridCertPathValidatorResult(result, null, false);
        }
        try {
            X509Certificate cert = (X509Certificate) certPath.getCertificates().get(0);
            SubjectPublicKeyInfo hyridKey = HybridKey.fromCert(cert).getKey();
            return new HybridCertPathValidatorResult(result, QTESLAUtils.fromSubjectPublicKeyInfo(hyridKey), true);
        } catch (IOException e) {
            throw new CertPathValidatorException(e.getMessage());
        }
    }
}
