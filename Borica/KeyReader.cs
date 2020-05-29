using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Borica
{
    public class KeyReader
    {
        /**
    * Read a key / certificate file and return its contents.
    *
    * @param $key
    * @return string
    */
        public static string ReadFile(string key)
        {
            Stream fp = File.OpenRead(key);
            byte[] read = new byte[8192];
            fp.Read(read, 0, 8192);
            fp.Dispose();

            return Encoding.UTF8.GetString(read);
        }

        public static RSA ReadKeyFromPem(string pemContents, string password = null, bool readPublic = false)
        {
            if (!readPublic)
            {
                const string RsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
                const string RsaPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
                const string EncRsaPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
                const string EncRsaPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";
                const string PrivateKeyHeader = "-----BEGIN PRIVATE KEY-----";
                const string PrivateKeyFooter = "-----END PRIVATE KEY-----";

                if (pemContents.IndexOf(RsaPrivateKeyHeader) > -1)
                {
                    int endIdx = pemContents.IndexOf(RsaPrivateKeyFooter, StringComparison.Ordinal);

                    int startIdx = pemContents.IndexOf(RsaPrivateKeyHeader) + RsaPrivateKeyHeader.Length;

                    string base64 = pemContents.Substring(
                        startIdx,
                        endIdx - startIdx);

                    byte[] der = Convert.FromBase64String(base64);
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(der, out _);
                    return rsa;
                }
                else if (pemContents.IndexOf(EncRsaPrivateKeyHeader) > -1)
                {
                    int endIdx = pemContents.IndexOf(EncRsaPrivateKeyFooter, StringComparison.Ordinal);
                    int startIdx = pemContents.IndexOf(EncRsaPrivateKeyHeader) + EncRsaPrivateKeyHeader.Length;

                    string base64 = pemContents.Substring(
                        startIdx,
                        endIdx - startIdx);

                    byte[] der = Convert.FromBase64String(base64);
                    RSA rsa = RSA.Create();
                    var passwordBytes = Encoding.UTF8.GetBytes(password);
                    rsa.ImportEncryptedPkcs8PrivateKey(passwordBytes, der, out _);
                    return rsa;
                }
                else if (pemContents.IndexOf(PrivateKeyHeader) > -1)
                {
                    int endIdx = pemContents.IndexOf(PrivateKeyFooter, StringComparison.Ordinal);
                    int startIdx = pemContents.IndexOf(PrivateKeyHeader) + PrivateKeyHeader.Length;

                    string base64 = pemContents.Substring(
                         startIdx,
                         endIdx - startIdx);

                    byte[] der = Convert.FromBase64String(base64);
                    RSA rsa = RSA.Create();
                    rsa.ImportPkcs8PrivateKey(der, out _);
                    return rsa;
                }
            }
            else
            {
                const string RsaPublicKeyHeader = "-----BEGIN RSA PUBLIC KEY-----";
                const string RsaPublicKeyFooter = "-----END RSA PUBLIC KEY-----";
                const string PublicKeyHeader = "-----BEGIN PUBLIC KEY-----";
                const string PublicKeyFooter = "-----END PUBLIC KEY-----";

                if (pemContents.IndexOf(RsaPublicKeyHeader) > -1)
                {
                    int endIdx = pemContents.IndexOf(RsaPublicKeyFooter, StringComparison.Ordinal);
                    int startIdx = pemContents.IndexOf(RsaPublicKeyHeader) + RsaPublicKeyHeader.Length;

                    string base64 = pemContents.Substring(
                           startIdx,
                           endIdx - startIdx);

                    byte[] der = Convert.FromBase64String(base64);
                    RSA rsa = RSA.Create();

                    rsa.ImportRSAPublicKey(der, out _);
                    return rsa;
                }
                else if (pemContents.IndexOf(PublicKeyHeader) > -1)
                {
                    int endIdx = pemContents.IndexOf(PublicKeyFooter, StringComparison.Ordinal);
                    int startIdx = pemContents.IndexOf(PublicKeyHeader) + PublicKeyHeader.Length;

                    string base64 = pemContents.Substring(
                           startIdx,
                           endIdx - startIdx);

                    byte[] der = Convert.FromBase64String(base64);
                    RSA rsa = RSA.Create();

                    rsa.ImportSubjectPublicKeyInfo(der, out _);
                    return rsa;
                }
            }


            // "BEGIN PRIVATE KEY" (ImportPkcs8PrivateKey),
            // "BEGIN ENCRYPTED PRIVATE KEY" (ImportEncryptedPkcs8PrivateKey),
            // "BEGIN PUBLIC KEY" (ImportSubjectPublicKeyInfo),
            // "BEGIN RSA PUBLIC KEY" (ImportRSAPublicKey)
            // could any/all be handled here.
            throw new InvalidOperationException();
        }
    }
}