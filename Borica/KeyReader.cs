using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Borica
{
    public class KeyReader
    {
        public static RSA ReadPrivateKeyFromPKCS12(string path, string password)
        {
            X509Certificate2 pfx = new X509Certificate2(path, password, X509KeyStorageFlags.Exportable);
            RSA rsa = pfx.GetRSAPrivateKey();
            return rsa;
        }

        public static RSA ReadPublicKey(string path, string password = null)
        {
            X509Certificate2 certificate = new X509Certificate2(path, password);
            RSA rsa = certificate.GetRSAPublicKey();
            return rsa;
        }
    }
}