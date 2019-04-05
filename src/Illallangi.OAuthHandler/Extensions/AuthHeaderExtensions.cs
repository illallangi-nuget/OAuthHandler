using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace Illallangi.Extensions
{
    public static class AuthHeaderExtensions
    {   
        // (Get-AuthorizationHeader -OAuth $oauth -Args $args -Uri $uri -Method $method)
        public static string CalculateAuthHeader(this OAuthHmacSha1Handler handler, string nonce, string timestamp, IDictionary<string, string> args, Uri uri, HttpMethod method)
        {
            handler.Debug($"CalculateAuthHeader(handler:\"{handler}\", nonce:\"{nonce}\", timestamp:\"{timestamp}\", args:string[{args.Count}], uri:\"{uri}\", method:\"{method}\")");
            var hmacSha1Signature =
                handler.CalculateHmacSha1Signature(nonce, timestamp, args, uri, method);
            return handler.CalculateAuthHeaderUsingHmacSha1Signature(nonce, timestamp, hmacSha1Signature, uri);
        }

        // (Get-AuthorizationHeader -OAuth $oauth -NormalizedRequestParameters $normalizedRequestParametersEx -Uri $uri -Method $method)
        public static string CalculateAuthHeaderUsingNormalizedRequestParameters(this OAuthHmacSha1Handler handler, string nonce, string timestamp, string normalizedRequestParameters, Uri uri, HttpMethod method)
        {
            var hmacSha1Signature =
                handler.CalculateHmacSha1SignatureUsingNormalizedRequestParameters(
                    normalizedRequestParameters, uri, method);
            return handler.CalculateAuthHeaderUsingHmacSha1Signature(nonce, timestamp, hmacSha1Signature, uri);
        }

        // (Get-AuthorizationHeader -OAuth $oauth -Uri $uri -SignatureBaseString $signatureBaseStringEx)
        public static string CalculateAuthHeaderUsingSignatureBaseString(this OAuthHmacSha1Handler handler, string nonce, string timestamp, string signatureBaseString, Uri uri)
        {
            var hmacSha1Signature =
                handler.CalculateHmacSha1SignatureUsingSignatureBaseString(signatureBaseString);
            return handler.CalculateAuthHeaderUsingHmacSha1Signature(nonce, timestamp, hmacSha1Signature, uri);
        }

        // (Get-AuthorizationHeader -OAuth $oauth -Uri $uri -HmacSha1Signature $hmacSha1SignatureEx)
        public static string CalculateAuthHeaderUsingHmacSha1Signature(this OAuthHmacSha1Handler handler, string nonce, string timestamp, string hmacSha1Signature, Uri uri)
        {
            var header = $"OAuth realm=\"{uri.AbsoluteUri}\"";

            var dictionary = new Dictionary<string, string>
            {
                { "oauth_consumer_key", handler.Consumer.Key },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_timestamp", timestamp },
                { "oauth_token", handler.Token.Key },
                { "oauth_version", "1.0" },
                { "oauth_signature", hmacSha1Signature }
            };

            return string.Join(",\r\n                         ", new List<string> { header }.Union(dictionary.Keys.OrderBy(key => key).Select(key => $"{key}=\"{Uri.EscapeDataString(dictionary[key] ?? string.Empty)}\"")));
        }
    }
}