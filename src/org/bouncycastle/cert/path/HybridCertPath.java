package org.bouncycastle.cert.path;

import org.bouncycastle.cert.X509CertificateHolder;

import java.util.HashSet;

public class HybridCertPath {
    private final X509CertificateHolder[] certificates;

    public HybridCertPath(X509CertificateHolder[] certificates) {
        this.certificates = this.copyArray(certificates);
    }

    public X509CertificateHolder[] getCertificates() {
        return this.copyArray(this.certificates);
    }

    public CertPathValidationResult validate(CertPathValidation[] ruleSet) {
        CertPathValidationContext context = new CertPathValidationContext(new HashSet<>());

        for(int i = 0; i != ruleSet.length; ++i) {
            for(int j = this.certificates.length - 1; j >= 0; --j) {
                try {
                    context.setIsEndEntity(j == 0);
                    ruleSet[i].validate(context, this.certificates[j]);
                } catch (CertPathValidationException var6) {
                    return new CertPathValidationResult(context, j, i, var6);
                }
            }
        }

        return new CertPathValidationResult(context);
    }

    private X509CertificateHolder[] copyArray(X509CertificateHolder[] array) {
        X509CertificateHolder[] rv = new X509CertificateHolder[array.length];
        System.arraycopy(array, 0, rv, 0, rv.length);
        return rv;
    }

    public int length() {
        return this.certificates.length;
    }
}
