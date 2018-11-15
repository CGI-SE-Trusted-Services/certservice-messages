package org.certificateservices.messages

import org.apache.xml.security.utils.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.messages.utils.XMLEncrypter
import spock.lang.Specification
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_PKCS11_LIBRARY
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_PKCS11_SLOT
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_PKCS11_SLOT_PASSWORD
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_TRUSTSTORE_PATH
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_TRUSTSTORE_PASSWORD
import static org.certificateservices.messages.PKCS11MessageSecurityProvider.SETTING_ENCRYPTION_ALGORITHM_SCHEME

class PKCS11MessageSecurityProviderSpec extends Specification {
    PKCS11MessageSecurityProvider prov
    X509Certificate testCert
    X509Certificate testCertWithKeyUsage
    Properties config
    String signKeyKeyId
    def mockedProviderManager
    KeyStore dummyKeyStore

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
    }

    def setup(){
        CertificateFactory cf = CertificateFactory.getInstance("X.509","BC")
        testCert = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64Cert)))
        testCertWithKeyUsage = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(TestData.base64CertWithKeyUsage)))

        config = new Properties();
        config.setProperty(SETTING_PKCS11_LIBRARY, "/usr/lib/libeToken.so")
        config.setProperty(SETTING_PKCS11_SLOT, "0")
        config.setProperty(SETTING_PKCS11_SLOT_PASSWORD, "tGidBq0Eep")

        config.setProperty(SETTING_TRUSTSTORE_PATH, this.getClass().getResource("/testtruststore.jks").getPath())
        config.setProperty(SETTING_TRUSTSTORE_PASSWORD, "foo123")

        config.setProperty(SETTING_ENCRYPTION_ALGORITHM_SCHEME, " RSA_pkcs1_5_WITH_AES256 ")

        dummyKeyStore = KeyStore.getInstance("JKS")
        dummyKeyStore.load(new FileInputStream("src/test/resources/dummykeystore.jks"), "tGidBq0Eep".toCharArray())

        mockedProviderManager = Mock(PKCS11ProviderManager)
        mockedProviderManager.addPKCS11Provider(_) >> {InputStream config ->
            assert new String(config.bytes) == "name = CSMsgSecProv\nlibrary = /usr/lib/libeToken.so\nslot = 0\n"
        }
        mockedProviderManager.loadPKCS11Keystore(_) >> {List<Character> password ->
            assert password.toString() == "[tGidBq0Eep]"
            return dummyKeyStore
        }
        prov = new PKCS11MessageSecurityProvider(config, mockedProviderManager)

        signKeyKeyId = XMLEncrypter.generateKeyId(prov.getSigningCertificate().getPublicKey())
    }

    def "test"() {
        when:
        X509Certificate certificate = prov.getSigningCertificate()

        then:
        certificate != null
    }
}
