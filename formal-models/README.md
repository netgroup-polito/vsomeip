# Secure SOME/IP - Formal Models

This folder contains the complete formal models expressed in *extended pi
calculus* to describe the security protocol we designed to protect SOME/IP
communications. These models have been leveraged to formally verify that no
attacks are possible under certain assumptions by means of Proverif [1], an
automatic cryptographic protocol verifier based on the Dolev-Yao formal
modeling technique [2]. Specifically, [SecureSomeIP_FormalModel.pv](SecureSomeIP_FormalModel.pv) is
the general model expressing all the different queries that have been verified,
while [SecureSomeIP_ObservationalEquivalence.pv](SecureSomeIP_ObservationalEquivalence.pv)
models the concept of observational equivalence (i.e. to prove that an attacker
cannot distinguish between a legitimate message and a random message, once
encrypted).

### References
* [1]: B. Blanchet, “An efficient cryptographic protocol verifier based on prologrules,” in Proc. 14th IEEE Computer Security Foundations Workshop, Jun. 2001, pp. 82–96
* [2]: D. Dolev and A. Yao, “On the security of public key protocols,” IEEE Trans. Inf. Theory, vol. 29, no. 2, pp. 198–208, Mar. 1983