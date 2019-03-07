package org.bouncycastle.jce.provider;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.security.PublicKey;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;

public class HybridCertPathValidatorResult extends PKIXCertPathValidatorResult {

    private AsymmetricKeyParameter hybridKey;
    private boolean hybridChainValidated;

    public HybridCertPathValidatorResult(TrustAnchor trustAnchor, PolicyNode policyTree, PublicKey subjectPublicKey, AsymmetricKeyParameter hybridKey, boolean hybridChainValidated) {
        super(trustAnchor, policyTree, subjectPublicKey);
        this.hybridKey = hybridKey;
        this.hybridChainValidated = hybridChainValidated;
    }

    public HybridCertPathValidatorResult(PKIXCertPathValidatorResult result, AsymmetricKeyParameter hybridKey, boolean hybridChainValidated) {
        this(result.getTrustAnchor(), result.getPolicyTree(), result.getPublicKey(), hybridKey, hybridChainValidated);
    }

    public AsymmetricKeyParameter getHybridKey() {
        return hybridKey;
    }

    public boolean isHybridChainValidated() {
        return hybridChainValidated;
    }
}
