using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;

namespace Borica.Tests
{
    [TestClass]
    public class CertificateReadTest
    {
        const string DATA = "TEST TEST TEST";
        const string PFX_PATH = "magazine_enc.p12";
        const string PFX_PASSWORD = "12345";

        const string PEM_PATH = "magazine.crt";

        [TestMethod]
        public void ReadEncPrivateKeyFromPKCS12()
        {
            RSA rsa = KeyReader.ReadPrivateKeyFromPKCS12(PFX_PATH, PFX_PASSWORD);
            Assert.IsNotNull(rsa);
            rsa.Dispose();
        }

        [TestMethod]
        public void ReadPublicKeyFromPKCS12()
        {
            RSA rsa = KeyReader.ReadPublicKey(PFX_PATH, PFX_PASSWORD);
            Assert.IsNotNull(rsa);
            rsa.Dispose();
        }

        [TestMethod]
        public void ReadPublicKeyFromPem()
        {
            RSA rsa = KeyReader.ReadPublicKey(PEM_PATH, null);
            Assert.IsNotNull(rsa);
            rsa.Dispose();
        }

        [TestMethod]
        public byte[] SignData() 
        {
            RSA pkeyid = KeyReader.ReadPrivateKeyFromPKCS12(PFX_PATH, PFX_PASSWORD);

            byte[] signature = pkeyid.SignData(Encoding.Default.GetBytes(DATA), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            pkeyid.Dispose();

            Assert.IsNotNull(signature);
            return signature;
        }

        [TestMethod]
        public void VerifyData()
        {
            RSA cert = KeyReader.ReadPublicKey(PEM_PATH, null);

            byte[] signature = SignData();
            
            Assert.IsTrue(cert.VerifyData(Encoding.Default.GetBytes(DATA), signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));

            cert.Dispose();
        }

        [TestMethod]
        public byte[] EncriptData()
        {
            RSA pkeyid = KeyReader.ReadPrivateKeyFromPKCS12(PFX_PATH, PFX_PASSWORD);

            byte[] data = pkeyid.Encrypt(Encoding.Default.GetBytes(DATA), RSAEncryptionPadding.Pkcs1);
            pkeyid.Dispose();

            Assert.IsNotNull(data);
            return data;
        }

        [TestMethod]
        public void DecriptData()
        {
            RSA pkeyid = KeyReader.ReadPrivateKeyFromPKCS12(PFX_PATH, PFX_PASSWORD);

            byte[] data = EncriptData();

            byte[] decripted = pkeyid.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            pkeyid.Dispose();

            Assert.AreEqual(DATA, Encoding.Default.GetString(decripted));
        }
    }
}
