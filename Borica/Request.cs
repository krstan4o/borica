using Borica.Exceptions;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Borica
{
    public class Request
    {
        const int REGISTER_TRANSACTION = 10;
        const int PAY_PROFIT = 11;
        const int DELAYED_AUTHORIZATION_REQUEST = 21;
        const int DELAYED_AUTHORIZATION_COMPLETE = 22;
        const int DELAYED_AUTHORIZATION_REVERSAL = 23;
        const int REVERSAL = 40;
        const int PAYED_PROFIT_REVERSAL = 41;

        private readonly string[] SUPPORTED_VERSIONS = new string[] { "1.0", "1.1", "2.0" };

        private readonly string terminalId;
        private readonly string privateKey;
        private readonly string privateKeyPassword;
        private readonly bool useFileKeyReader;
        private readonly string language;
        private readonly bool debug;

        private readonly string gatewayURL = "https://gate.borica.bg/boreps/";
        private readonly string testGatewayURL = "https://gatet.borica.bg/boreps/";

        private string transactionCode;
        private decimal amount;
        private string orderId;
        private string description;
        private string currency = "EUR";


        public Request(string terminalId, string privateKey, string privateKeyPassword = "", string language = "", bool debug = false, bool useFileKeyReader = true)
        {
            this.terminalId = terminalId;
            this.privateKey = privateKey;
            this.privateKeyPassword = privateKeyPassword;
            this.useFileKeyReader = useFileKeyReader;
            this.language = language.ToUpper();
            this.debug = debug;
        }

    /**
    * Register a transaction with Borica.
    *
    * @param string $protocolVersion
    * @param string $oneTimeTicket
    * @return string
    */
        public string register(string protocolVersion = "1.1", string oneTimeTicket = null)
        {
            var message = getBaseMessage(REGISTER_TRANSACTION, protocolVersion);

            if (protocolVersion == "2.0") 
            {
                message.Add(oneTimeTicket.PadRight(6));
            }

            return generateURL(message, "registerTransaction");
        }

        /**
         * Check the status of a transaction with Borica.
         *
         * @param string $protocolVersion
         * @return string
         */
        public string status(string protocolVersion = "1.1")
        {
            var message = getBaseMessage(REGISTER_TRANSACTION, protocolVersion);

            return generateURL(message, "transactionStatusReport");
        }

        /**
         * Register a delayed request.
         *
         * @param string $protocolVersion
         * @return string
         */
        public string registerDelayedRequest(string protocolVersion = "1.1")
        {
            var message = getBaseMessage(DELAYED_AUTHORIZATION_REQUEST, protocolVersion);

            return generateURL(message);
        }

        /**
         * Complete an already registered transaction.
         *
         * @param string $protocolVersion
         * @return string
         */
        public string completeDelayedRequest(string protocolVersion = "1.1")
        {
            var message = getBaseMessage(DELAYED_AUTHORIZATION_COMPLETE, protocolVersion);

            return generateURL(message);
        }

        /**
         * Cancel already registered delayed request.
         *
         * @param string $protocolVersion
         * @return string
         */
        public string reverseDelayedRequest(string protocolVersion = "1.1")
        {
            var message = getBaseMessage(DELAYED_AUTHORIZATION_REVERSAL, protocolVersion);

            return generateURL(message);
        }

        /**
         * Reverse a payment.
         *
         * @param string $protocolVersion
         * @return string
         */
        public string reverse(string protocolVersion = "1.1")
        {
            var message = getBaseMessage(REVERSAL, protocolVersion);

            return generateURL(message);
        }

        public string getDate()
        {
            return DateTime.Now.ToString("YmdHis");
        }

        public string getAmount()
        {
            validateAmount(amount);
            return amount.ToString().PadLeft(12, '0');
        }

        public string getTerminalId()
        {
            return terminalId;
        }

        public string getOrderId()
        {
            validateOrderId(orderId);
            return orderId.PadRight(15);
        }

        public string getDescription()
        {
            validateDescription(description);
            return description.PadRight(125);
        }

        public string getLanguage()
        {
            return (language == "BG" || language == "EN") ? language : "EN";
        }

        public string getCurrency()
        {
            return currency;
        }

        public Request TransactionCode(string code)
        {
            transactionCode = code;

            return this;
        }

        public Request Amount(decimal amount)
        {
            validateAmount(amount);

            this.amount = amount * 100;

            return this;
        }

        public Request OrderId(string id)
        {
            validateOrderId(id);

            orderId = id;

            return this;
        }

        public Request Description(string desc)
        {
            validateDescription(desc);

            description = desc;

            return this;
        }

        public Request Currency(string currency)
        {
            this.currency = currency.ToUpper();
            return this;
        }

        /**
         * Ensure that the protocol version is correct.
         *
         * @param $protocolVersion
         * @return bool
         */
        public string getProtocolVersion(string protocolVersion)
        {
            for (int i = 0; i < SUPPORTED_VERSIONS.Length; i++)
            {
                if (SUPPORTED_VERSIONS[i] == protocolVersion)
                {
                    return protocolVersion;
                }
            }

            return "1.1";
        }

        /**
         * Get the proper gateway url.
         *
         * @return string
         */
        public string getGatewayURL()
        {
            return debug ? testGatewayURL : gatewayURL;
        }

        /**
         * Generate the request URL for Borica.
         * 
         * @param $message
         * @param string $type
         * @return string
         */
        public string generateURL(object message, string type = "manageTransaction")
        {
            string msg = signMessage(message);

            var bytes = Encoding.UTF8.GetBytes(msg);
            string base64 = Convert.ToBase64String(bytes);
            
            return getGatewayURL() + type + "?eBorica=" + WebUtility.UrlEncode(base64);
        }


        /**
         * Read the private key contents and return it.
         *
         * @return string
         */
        public string getPrivateKey()
        {
            if (useFileKeyReader) {
                return KeyReader.ReadFile(privateKey);
            }

            return privateKey;
        }

        /**
         * Sign the message with the private key of the merchant.
         *
         * @param $message
         * @return mixed
         */
        public string signMessage(object message)
        {
            string msg;

            if (message is List<string>)
            {
                var t = message as List<string>;
                msg = string.Join("", t);
            }
            else
                msg = message.ToString();

            RSA pkeyid = KeyReader.ReadKeyFromPem(getPrivateKey(), privateKeyPassword);

            byte[] signature = pkeyid.SignData(Encoding.UTF8.GetBytes(msg), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            pkeyid.Dispose();

            return msg + Encoding.UTF8.GetString(signature);
        }

        /**
         * Get the base message structure.
         *
         * @param $messageType
         * @param string $protocolVersion
         * @return array
         */
        protected List<string> getBaseMessage(int messageType, string protocolVersion = "1.1")
        {
            protocolVersion = getProtocolVersion(protocolVersion);

            var message = new List<string>() {
                messageType.ToString(),
                getDate(),
                getAmount(),
                getTerminalId(),
                getOrderId(),
                getDescription(),
                getLanguage(),
                protocolVersion
            };

            if (protocolVersion != "1.0") {
                message.Add(getCurrency());
            }

            return message;
        }

        /**
         * @param $amount
         */
        private void validateAmount(decimal amount)
        {
            //if (!is_numeric($amount))
            //{
            //    throw new InvalidParameterException("The amount should be a number!");
            //}
        }

        /**
         * @param string $desc
         */
        private void validateDescription(string desc)
        {
            if (desc == null || desc.Length < 1 || desc.Length > 125) {
                throw new LengthException("The description of the request should be between 1 and 125 symbols.");
            }
        }

        /**
         * @param $id
         */
        private void validateOrderId(string id)
        {
            int idLength = id.Length;

            if (idLength < 1 || idLength > 15) {
                throw new LengthException("The order id should be between 1 and 15 symbols.");
            }
        }
    }
}
