namespace Borica
{
    public class Factory
    {
        public Request Request { get; private set; }

        private readonly Response response;

        public Factory(Request request, Response response)
        {
            Request = request;
            this.response = response;
        }

        public Response GetResponse(string message) 
        {
            if (!string.IsNullOrEmpty(message))
            {
                return response.parse(message);
            }

            return response;
        }
    }
}
