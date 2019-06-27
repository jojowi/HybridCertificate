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
            exception.printStackTrace();
            return new HybridCertPathValidatorResult(result, null, false);
        }
        try {
            X509Certificate cert = (X509Certificate) certPath.getCertificates().get(0);
            if (cert.getNonCriticalExtensionOIDs().contains(HybridKey.OID))
                return new HybridCertPathValidatorResult(result, QTESLAUtils.fromSubjectPublicKeyInfo(HybridKey.fromCert(cert).getKey()), true);
            else
                return new HybridCertPathValidatorResult(result, null, true);
        } catch (IOException e) {
            throw new CertPathValidatorException(e.getMessage());
        }
    }
}
