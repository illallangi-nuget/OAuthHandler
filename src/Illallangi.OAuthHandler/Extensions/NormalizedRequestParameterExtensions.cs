using System;
using System.Collections.Generic;
using System.Linq;

namespace Illallangi.Extensions
{
    public static class NormalizedRequestParameterExtensions
    {
        // (Get-NormalizedRequestParameters -OAuth $oauth -Args $args)
        public static string CalculateNormalizedRequestParameters(
            this OAuthHmacSha1Handler handler,
            string nonce, 
            string timestamp, 
            IDictionary<string, string> args)
        {
            var dictionary = args.Concat(new Dictionary<string, string>
                {
                    { "oauth_consumer_key", handler.Consumer.Key },
                    { "oauth_nonce", nonce },
                    { "oauth_signature_method", "HMAC-SHA1" },
                    { "oauth_timestamp", timestamp },
                    { "oauth_token", handler.Token.Key },
                    { "oauth_version", "1.0" }
                }).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            return string.Join("&", dictionary.Keys.OrderBy(key => key).Select(key => $"{key}={Uri.EscapeDataString(dictionary[key])}"));
        }
    }
}