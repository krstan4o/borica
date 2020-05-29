using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Borica
{
    public class Response
    {
        const string TRANSACTION_CODE = "TRANSACTION_CODE";
        const string TRANSACTION_TIME = "TRANSACTION_TIME";
        const string AMOUNT = "AMOUNT";
        const string TERMINAL_ID = "TERMINAL_ID";
        const string ORDER_ID = "ORDER_ID";
        const string RESPONSE_CODE = "RESPONSE_CODE";
        const string PROTOCOL_VERSION = "PROTOCOL_VERSION";
        const string SIGN = "SIGN";
        const string SIGNATURE_OK = "SIGNATURE_OK";

        private readonly string publicCertificate;
        private readonly bool useFileKeyReader;

        private Dictionary<string, object> response;

        public Response(string publicCertificate, bool useFileKeyReader = true)
        {
            this.publicCertificate = publicCertificate;
            this.useFileKeyReader = useFileKeyReader;
        }

        public Response parse(string message)
        {
            byte[] data = Convert.FromBase64String(message);
            string decodedString = Encoding.UTF8.GetString(data);
            message = decodedString;

            response = new Dictionary<string, object>()
            {
                { TRANSACTION_CODE  , message.Substring(0, 2) },
                { TRANSACTION_TIME  , message.Substring(2, 14) },
                { AMOUNT            , message.Substring(16, 12)},
                { TERMINAL_ID       , message.Substring(28, 8)},
                { ORDER_ID          , message.Substring(36, 15)},
                { RESPONSE_CODE     , message.Substring(51, 2)},
                { PROTOCOL_VERSION  , message.Substring(53, 3)},
                { SIGN              , message.Substring(56, 128)},
                { SIGNATURE_OK      , VerifySignature(message, message.Substring(56, 128)) }
            };

            return this;
        }

        public string transactionCode()
        {
            return response[TRANSACTION_CODE].ToString();
        }

        public DateTime transactionTime()
        {
            return DateTime.ParseExact(response[TRANSACTION_TIME].ToString(), "YMdHms", CultureInfo.InvariantCulture);
            //return Carbon::createFromFormat("YmdHms", response[TRANSACTION_TIME]);
        }

        public float amount()
        {
            return (float)response[AMOUNT] / 100;
        }

        public string terminalID()
        {
            return response[TERMINAL_ID].ToString();
        }

        public string orderID()
        {
            return response[ORDER_ID].ToString().Trim();
        }

        public string responseCode()
        {
            return response[RESPONSE_CODE].ToString();
        }

        public string protocolVersion()
        {
            return response[PROTOCOL_VERSION].ToString();
        }

        public string signatureOk()
        {
            return response[SIGNATURE_OK].ToString();
        }

        public bool IsSuccessful()
        {
            return responseCode() == "00";
        }

        public bool NotSuccessful()
        {
            return !IsSuccessful();
        }

        /**
         * Verify the returned response.
         *
         * @param $message
         * @param $signature
         * @return mixed
         */
        public bool VerifySignature(string message, string signature)
        {
            RSA pubkeyid = getCertificate();

            bool verify = pubkeyid.VerifyData(Encoding.UTF8.GetBytes(message.Substring(0, message.Length - 128)), Encoding.UTF8.GetBytes(signature), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            // openssl_free_key(pubkeyid);
            pubkeyid.Dispose();

            return verify;
        }

        public RSA getCertificate()
        {
            if (useFileKeyReader) {
                string contents = KeyReader.ReadFile(publicCertificate);
                return KeyReader.ReadKeyFromPem(contents, null, true);
            }

            return KeyReader.ReadKeyFromPem(publicCertificate, null, true);
        }
    }
}
