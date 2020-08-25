using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace Borica.Tests
{
    [TestClass]
    public class CertificateReadTest
    {
        [TestMethod]
        public void ReadPrivateRsaPemFile()
        {
            string content = ReadFileContents("private-openssl-rsa.pem");
            RSA rsa = KeyReader.ReadKeyFromPem(content, null, false);
            Assert.IsNotNull(rsa);
        }

        [TestMethod]
        public void ReadPrivateEncRsaPemFile()
        {
            string content = ReadFileContents("private-openssl-enc-rsa.pem");
            RSA rsa = KeyReader.ReadKeyFromPem(content, "1234", false);
            Assert.IsNotNull(rsa);
        }

        [TestMethod]
        public void ReadPrivatePemFile()
        {
            string content = ReadFileContents("private-openssl.pem");
            RSA rsa = KeyReader.ReadKeyFromPem(content, null, false);
            Assert.IsNotNull(rsa);
        }

        [TestMethod]
        public void ReadPrivateEncPemFile()
        {
            string content = ReadFileContents("private-openssl-enc.pem");
            RSA rsa = KeyReader.ReadKeyFromPem(content, "1234", false);
            Assert.IsNotNull(rsa);
        }

        private string ReadFileContents(string path) 
        {
            return KeyReader.ReadFile(path);
        }
    }
}
