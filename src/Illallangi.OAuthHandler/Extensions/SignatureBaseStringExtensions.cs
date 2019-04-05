using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace Illallangi.Extensions
{
    public static class SignatureBaseStringExtensions
    {
        public static string CalculateSignatureBaseString(
            this OAuthHmacSha1Handler handler, 
            string nonce,
            string timestamp, 
            IDictionary<string, string> args, 
            Uri uri, 
            HttpMethod method)
        {
            var normalizedRequestParameters =
                handler.CalculateNormalizedRequestParameters(nonce, timestamp, args);
            return handler.CalculateSignatureBaseStringUsingNormalizedRequestParameters(
                normalizedRequestParameters, uri, method);
        }

        public static string CalculateSignatureBaseStringUsingNormalizedRequestParameters(
            // ReSharper disable once UnusedParameter.Global
            this OAuthHmacSha1Handler handler,
            string normalizedRequestParameters,
            Uri uri,
            HttpMethod method)
        {
            var list = new[] { method.ToString(), uri.GetLeftPart(UriPartial.Path), normalizedRequestParameters };
            return string.Join("&", list.Select(Uri.EscapeDataString));
        }
    }
}