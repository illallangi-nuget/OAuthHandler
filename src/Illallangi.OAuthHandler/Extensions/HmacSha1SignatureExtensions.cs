using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Illallangi.Extensions
{
    public static class HmacSha1SignatureExtensions
    {
        public static string CalculateHmacSha1Signature(
            this OAuthHmacSha1Handler handler, 
            string nonce,
            string timestamp, 
            IDictionary<string, string> args, 
            Uri uri, 
            HttpMethod method)
        {
            var signatureBaseString =
                handler.CalculateSignatureBaseString(nonce, timestamp, args, uri, method);
            return handler.CalculateHmacSha1SignatureUsingSignatureBaseString(
                signatureBaseString);
        }

        public static string CalculateHmacSha1SignatureUsingNormalizedRequestParameters(
            this OAuthHmacSha1Handler handler, 
            string normalizedRequestParameters, 
            Uri uri,
            HttpMethod method)
        {
            var signatureBaseString =
                handler.CalculateSignatureBaseStringUsingNormalizedRequestParameters(
                    normalizedRequestParameters, uri, method);
            return handler.CalculateHmacSha1SignatureUsingSignatureBaseString(
                signatureBaseString);
        }

        public static string CalculateHmacSha1SignatureUsingSignatureBaseString(
            this OAuthHmacSha1Handler handler, string signatureBaseString)
        {
            var sha = System.Security.Cryptography.KeyedHashAlgorithm.Create("HMACSHA1");
            sha.Key = System.Text.Encoding.UTF8.GetBytes($"{handler.Consumer.Secret}&{handler.Token.Secret}");
            return Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signatureBaseString)));
        }
    }
}