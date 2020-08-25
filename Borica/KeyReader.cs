using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
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
                        endIdx - startIdx).Trim();

                    byte[] der = null;
                    try
                    {
                        der = Convert.FromBase64String(base64);
                        
                    }
                    catch (FormatException)
                    {
                        StringReader str = new StringReader(base64);

                        //-------- read PEM encryption info. lines and extract salt -----
                        if (!str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED"))
                            return null;

                        string saltline = str.ReadLine();
                        if (!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,"))
                            return null;

                        string saltstr = saltline.Substring(saltline.IndexOf(",") + 1).Trim();
                        byte[] salt = new byte[saltstr.Length / 2];
                        for (int i = 0; i < salt.Length; i++)
                            salt[i] = Convert.ToByte(saltstr.Substring(i * 2, 2), 16);
                        if (!(str.ReadLine() == ""))
                            return null;

                        //------ remaining b64 data is encrypted RSA key ----
                        string encryptedstr = str.ReadToEnd();

                        try
                        {   //should have b64 encrypted RSA key now
                            der = Convert.FromBase64String(encryptedstr);
                        }
                        catch (FormatException)
                        {  // bad b64 data.
                            return null;
                        }

                        //------ Get the 3DES 24 byte key using PDK used by OpenSSL ----
                        byte[] deskey = GetOpenSSL3deskey(salt, password, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
                        if (deskey == null)
                            return null;
                        //showBytes("3DES key", deskey) ;

                        //------ Decrypt the encrypted 3des-encrypted RSA private key ------
                        der = DecryptKey(der, deskey, salt);   //OpenSSL uses salt value in PEM header also as 3DES IV
                       
                    }
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

        private static byte[] GetOpenSSL3deskey(byte[] salt, string secpswd, int count, int miter)
        {
            IntPtr unmanagedPswd = IntPtr.Zero;
            int HASHLENGTH = 16;    //MD5 bytes
            byte[] keymaterial = new byte[HASHLENGTH * miter];     //to store contatenated Mi hashed results


            byte[] psbytes = Encoding.Default.GetBytes(secpswd);

            //UTF8Encoding utf8 = new UTF8Encoding();
            //byte[] psbytes = utf8.GetBytes(pswd);

            // --- contatenate salt and pswd bytes into fixed data array ---
            byte[] data00 = new byte[psbytes.Length + salt.Length];
            Array.Copy(psbytes, data00, psbytes.Length);        //copy the pswd bytes
            Array.Copy(salt, 0, data00, psbytes.Length, salt.Length);   //concatenate the salt bytes

            // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] result = null;
            byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

            for (int j = 0; j < miter; j++)
            {
                // ----  Now hash consecutively for count times ------
                if (j == 0)
                    result = data00;    //initialize 
                else
                {
                    Array.Copy(result, hashtarget, result.Length);
                    Array.Copy(data00, 0, hashtarget, result.Length, data00.Length);
                    result = hashtarget;
                    //Console.WriteLine("Updated new initial hash target:") ;
                    //showBytes(result) ;
                }

                for (int i = 0; i < count; i++)
                    result = md5.ComputeHash(result);
                Array.Copy(result, 0, keymaterial, j * HASHLENGTH, result.Length);  //contatenate to keymaterial
            }
            //showBytes("Final key material", keymaterial);
            byte[] deskey = new byte[24];
            Array.Copy(keymaterial, deskey, deskey.Length);

            Array.Clear(psbytes, 0, psbytes.Length);
            Array.Clear(data00, 0, data00.Length);
            Array.Clear(result, 0, result.Length);
            Array.Clear(hashtarget, 0, hashtarget.Length);
            Array.Clear(keymaterial, 0, keymaterial.Length);

            return deskey;
        }

        // ----- Decrypt the 3DES encrypted RSA private key ----------

        public static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV)
        {
            MemoryStream memst = new MemoryStream();
            TripleDES alg = TripleDES.Create();
            alg.Key = desKey;
            alg.IV = IV;
            try
            {
                CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(cipherData, 0, cipherData.Length);
                cs.Close();
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                return null;
            }
            byte[] decryptedData = memst.ToArray();
            return decryptedData;
        }
    }
}