package org.bouncycastle.cert.path.validations;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationContext;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.util.Memoable;

public class HybridValidation implements CertPathValidation {

    @Override
    public void validate(CertPathValidationContext certPathValidationContext, X509CertificateHolder x509CertificateHolder) throws CertPathValidationException {
        
    }

    @Override
    public Memoable copy() {
        return new HybridValidation();
    }

    @Override
    public void reset(Memoable memoable) {

    }
}
