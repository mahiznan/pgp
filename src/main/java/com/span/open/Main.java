package com.span.open;

import org.pgpainless.sop.SOPImpl;
import sop.ByteArrayAndResult;
import sop.DecryptionResult;
import sop.SOP;
import sop.Verification;

import java.io.IOException;
import java.util.List;

public class Main {
    public static void main(String[] args) throws IOException {
        SOP sop = new SOPImpl();

// Generate an OpenPGP key
        byte[] key = sop.generateKey()
                .userId("Alice <alice@example.org>")
                .generate()
                .getBytes();

// Extract the certificate (public key)
        byte[] cert = sop.extractCert()
                .key(key)
                .getBytes();

// Encrypt a message
        byte[] message = "custom_message".getBytes();
        byte[] encrypted = sop.encrypt()
                .withCert(cert)
                .signWith(key)
                .plaintext(message)
                .getBytes();

// Decrypt a message
        ByteArrayAndResult<DecryptionResult> messageAndVerifications = sop.decrypt()
                .verifyWithCert(cert)
//                .verifyWith(cert)
                .withKey(key)
                .ciphertext(encrypted)
                .toByteArrayAndResult();
        byte[] decrypted = messageAndVerifications.getBytes();
// Signature Verifications
        DecryptionResult messageInfo = messageAndVerifications.getResult();
        List<Verification> signatureVerifications = messageInfo.getVerifications();
        System.out.println("Signature verifications: " + signatureVerifications);
    }
}