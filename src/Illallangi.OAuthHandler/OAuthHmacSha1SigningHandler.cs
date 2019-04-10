using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Illallangi.Extensions;
using Newtonsoft.Json;

namespace Illallangi
{
    [JsonObject(MemberSerialization.OptIn)]
    public sealed class OAuthHmacSha1SigningHandler : DelegatingHandler
    {
        public const string AuthorizationHeader = @"Authorization: OAuth realm=""" + RealmPlaceholder + @"""," +
                                                  @"oauth_consumer_key=""" + ConsumerKeyPlaceholder + @"""," +
                                                  @"oauth_nonce=""" + NoncePlaceholder + @"""," +
                                                  @"oauth_signature=""" + SignaturePlaceholder + @"""," +
                                                  @"oauth_signature_method=""" + SignatureMethodPlaceholder + @"""," +
                                                  @"oauth_timestamp=""" + TimestampPlaceholder + @"""," +
                                                  @"oauth_token=""" + TokenPlaceholder + @"""," +
                                                  @"oauth_version=""" + VersionPlaceholder + @"""";

        public const string RealmPlaceholder = @"21919afe-4492-4bbb-85a2-977f0259b02b";
        public const string ConsumerKeyPlaceholder = @"3758747f-cacb-49f6-8fab-4eb182c3af34";
        public const string NoncePlaceholder = @"4b41486a-37dd-4a64-8d47-6e93f8bcf900";
        public const string SignaturePlaceholder = @"9525a02d-c397-4f8c-bf5d-56c0d2fbf599";
        public const string SignatureMethodPlaceholder = @"9b4ac3fb-a46d-43d6-8ec4-ae3b4dff1d6d";
        public const string TimestampPlaceholder = @"868ae57b-d832-48ff-8386-540c9b64b1b9";
        public const string TokenPlaceholder = @"9472de36-bf72-4e99-810e-b9d917942711";
        public const string VersionPlaceholder = @"5e8e6e6a-df88-49fb-a6d3-0c88930f2fe4";
        public const string MethodPlaceholder = @"e97b2fab-713f-4958-a22a-1e25dabebd41";
        public const string RequestPlaceholder = @"2868e660-39ce-478f-a070-fa56a79d8283";

        private const int NonceLength = 40;

        #region Constructor

        public OAuthHmacSha1SigningHandler(
                HttpMessageHandler innerHandler, 
                IOAuthSetting setting) :
            base(innerHandler)
        {
            Setting = setting ?? throw new ArgumentNullException(nameof(setting));
        }

        #endregion

        #region Properties

        [JsonProperty(@"config")]
        public IOAuthSetting Setting { get; }

        #endregion

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var placeholders = new Dictionary<string, KeyValuePair<string, string>>
            {
                {"realm", new KeyValuePair<string, string>(RealmPlaceholder, request.RequestUri.AbsoluteUri.Replace(request.RequestUri.PathAndQuery, @"/"))},
                {"request", new KeyValuePair<string, string>(RequestPlaceholder, request.RequestUri.GetRequest())},
                {"consumerKey", new KeyValuePair<string, string>(ConsumerKeyPlaceholder, Setting.ConsumerKey)},
                {"nonce", new KeyValuePair<string, string>(NoncePlaceholder, GenerateNonce())},
                {"signatureMethod", new KeyValuePair<string, string>(SignatureMethodPlaceholder, "HMAC-SHA1")},
                {"timestamp", new KeyValuePair<string, string>(TimestampPlaceholder, GenerateTimeStamp())},
                {"token", new KeyValuePair<string, string>(TokenPlaceholder, Setting.AuthorizedKey)},
                {"version", new KeyValuePair<string, string>(VersionPlaceholder, "1.0")},
                {"method", new KeyValuePair<string, string>(MethodPlaceholder, request.Method.Method.ToUpperInvariant())},
            };
            
            IDictionary<string, IEnumerable<string>> postData = null;
            IDictionary<string, IEnumerable<string>> headerData = null;
            IDictionary<string, IEnumerable<string>> authorizationData = null;
            IDictionary<string, IEnumerable<string>> queryData = null;

            if (request.Content?.Headers?.ContentType != null && request.Content.Headers.ContentType.MediaType == "application/x-www-form-urlencoded")
            {
                postData = HttpUtility
                    .ParseQueryString(request.Content.ReadAsStringAsync().Result)
                    .ToDictionary()
                    .ReplacePlaceholders(placeholders);
            }

            if (request.Headers != null)
            {
                headerData = request
                    .Headers
                    .ToDictionary(h => h.Key, h => h.Value)
                    .ReplacePlaceholders(placeholders);
            }

            if (headerData != null && headerData.ContainsKey(@"Authorization"))
            {
                authorizationData = new Dictionary<string, IEnumerable<string>>();
                foreach (Match match in Regex.Matches(headerData[@"Authorization"].Single(),@"(([^= ,]*?)\=\""([^""]*?)\"",?)"))
                {
                    authorizationData.Add(match.Groups[2].Value, new[] {match.Groups[3].ToString()});
                }
            }

            if (!string.IsNullOrWhiteSpace(request.RequestUri.Query))
            {
                queryData = HttpUtility
                    .ParseQueryString(request.RequestUri.Query)
                    .ToDictionary();
                    // .ReplacePlaceholders(placeholders);
            }

            
            var normalizedRequestParameters = NormalizeRequestParameters(postData, authorizationData, queryData);
            var signatureBaseString = string.Join("&", 
                Uri.EscapeDataString(placeholders["method"].Value),
                Uri.EscapeDataString(placeholders["request"].Value),
                Uri.EscapeDataString(normalizedRequestParameters));
            
            var sha = KeyedHashAlgorithm.Create("HMACSHA1");
            sha.Key = Encoding.UTF8.GetBytes($"{Setting.ConsumerSecret}&{Setting.AuthorizedSecret}");
            placeholders.Add("signature",
                new KeyValuePair<string, string>(SignaturePlaceholder,
                    Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(signatureBaseString)))));

            postData = postData.ReplacePlaceholders(placeholders);
            headerData = headerData.ReplacePlaceholders(placeholders);

            if (postData != null)
            {
                request.Content = new FormUrlEncodedContent(postData.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Single()));
            }

            if (headerData != null && request.Headers != null)
            {
                request.Headers.Clear();
                foreach (var kvp in headerData)
                {
                    request.Headers.Add(kvp.Key, kvp.Value);
                }
            }

            return await base.SendAsync(request, cancellationToken);
        }

        private string NormalizeRequestParameters(params IEnumerable<KeyValuePair<string, IEnumerable<string>>>[] args)
        {
            if (null == args)
            {
                return string.Empty;
            }
            return string.Join("&",
                args
                    .Where(i => null != i)
                    .SelectMany(i => i) // Flatten array of dictionaries
                    .Where(i => !i.Key.Equals(@"oauth_signature")) // Remove oauth_signature
                    .Where(i => !i.Key.Equals(@"realm")) // Remove realm
                    .ToDictionary(k => k.Key, v => v.Value) // Convert to dictionary
                    .OrderBy(k => k.Key) // Sort by key TODO: Sort by key and value
                    .Select(kvp => $"{kvp.Key}={kvp.Value.Single()}") // Separate key and value by =
                    .ToArray());
        }

        public string GenerateNonce()
        {
            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

            var data = new byte[1];
            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[NonceLength];
                crypto.GetNonZeroBytes(data);
            }

            var result = new StringBuilder(NonceLength);
            foreach (var b in data)
            {
                result.Append(chars[b % chars.Length]);
            }

            return result.ToString();
        }

        private static string GenerateTimeStamp()
        {
            return Math.Truncate((DateTime.Now.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }
    }
}
