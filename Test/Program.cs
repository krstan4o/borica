using Borica;
using System.Net.Http;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            //ReadKeyFromFile(@"C:\Users\Krastanp\Desktop\example.org.key", "D@tas0l");

            //string message = "Teste Teste";

            //RSA pkeyid = ReadKeyFromFile(@"C:\Users\Krastanp\Desktop\example.org.key", "D@tas0l");
            //byte[] signature = pkeyid.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            //pkeyid.Dispose();

            //Console.WriteLine(message + Encoding.UTF8.GetString(signature));

            Request request = new Request("12345", @"C:\Users\Krastanp\Desktop\example.org.pem", "D@tas0l", "BG", true, true);
            
            Factory factory = new Factory(request, new Response(@"C:\Users\Krastanp\Desktop\example.org.pub.key", true));
            string registerUrl = factory.Request.Amount(1).Description("test payment").OrderId("1").Currency("EUR").register();
            //var res = new Response(@"C:\Users\Krastanp\Desktop\example.org.pem", true);
            //res.getCertificate();
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                var response = client.GetAsync(registerUrl).Result;
                response.EnsureSuccessStatusCode();

                string content = response.Content.ReadAsStringAsync().Result;

            }
        }
    }
}
