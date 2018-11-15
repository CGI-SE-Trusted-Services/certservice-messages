package org.certificateservices.messages;

import sun.security.pkcs11.SunPKCS11;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public class DefaultPKCS11ProviderManager implements PKCS11ProviderManager {
    public void addPKCS11Provider(InputStream config) throws SecurityException, NullPointerException, ProviderException {
        SunPKCS11 pkcs11Provider = new SunPKCS11(config);
        if(pkcs11Provider != null){
            Security.addProvider(pkcs11Provider);
        }
    }

    public KeyStore loadPKCS11Keystore(char[] password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS11");
        keyStore.load(null, password);
        return keyStore;
    }
}
