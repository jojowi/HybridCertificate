package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.HybridCertPath;
import org.bouncycastle.cert.path.validations.HybridValidation;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;

public class HybridCertPathValidatorSpi extends PKIXCertPathValidatorSpi {

    @Override
    public HybridCertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) super.engineValidate(certPath, params);

        HybridCertPath path = new HybridCertPath(certPath.getCertificates().stream().map(cert -> {
            try {
                return new X509CertificateHolder(cert.getEncoded());
            } catch (IOException | CertificateEncodingException e) {
                e.printStackTrace();
            }
            return null;
        }).toArray(X509CertificateHolder[]::new));
        CertPathValidation[] val = {new HybridValidation()};
        CertPathValidationResult validate = path.validate(val);
        if (validate.isValid()) {
            try {
                X509Certificate cert = new JcaX509CertificateConverter().getCertificate(path.getCertificates()[0]);
                SubjectPublicKeyInfo hyridKey = HybridKey.fromCert(cert).getKey();
                return new HybridCertPathValidatorResult(result, QTESLAUtils.fromSubjectPublicKeyInfo(hyridKey), true);
            } catch (CertificateException | IOException e) {
                throw new CertPathValidatorException(e.getMessage());
            }
        } else {
            return new HybridCertPathValidatorResult(result, null, false);
        }
    }
}
