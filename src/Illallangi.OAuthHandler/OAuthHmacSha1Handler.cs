using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Illallangi.Extensions;

namespace Illallangi
{
    public sealed class OAuthHmacSha1Handler : DelegatingHandler
    {
        #region Constructors

        public OAuthHmacSha1Handler(HttpMessageHandler innerHandler, OAuthToken consumer, OAuthToken token = null, int nonceLength = 40, Action<string> debug = null) :
            base(innerHandler)
        {
            this.Consumer = consumer ?? throw new ArgumentNullException(nameof(consumer));
            this.Token = token ?? new OAuthToken(string.Empty, string.Empty);
            this.NonceLength = nonceLength;
            this.Debug = debug ?? (str => { });
        }

        #endregion

        #region Properties

        public OAuthToken Consumer { get; }

        public OAuthToken Token { get; }

        public int NonceLength { get; }

        public Action<string> Debug { get; }

        #endregion

        #region Methods
        public override string ToString()
        {
            return $"{base.ToString()}(innerHandler,consumer:{this.Consumer},token:{this.Token},noncelength:{this.NonceLength})";
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var authHeader = this.CalculateAuthHeader(
                this.GenerateNonce(), 
                DateTime.Now.GenerateTimeStamp(), 
                request.CalculateArgs(),
                request.RequestUri, 
                request.Method);

            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", authHeader);
            return await base.SendAsync(request, cancellationToken);
        }

        #endregion
    }
}