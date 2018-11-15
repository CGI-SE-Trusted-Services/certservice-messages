package org.certificateservices.messages;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public interface PKCS11ProviderManager {
    void addPKCS11Provider(InputStream config) throws SecurityException, NullPointerException, ProviderException;
    KeyStore loadPKCS11Keystore(char[] password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException;
}
