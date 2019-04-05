using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web;

namespace Illallangi.Extensions
{
    public static class HttpRequestExtensions
    {
        public static IDictionary<string, string> CalculateArgs(this HttpRequestMessage request)
        {
            IDictionary<string, string> result = new Dictionary<string, string>();

            if (request.Content != null)
            {
                if (request.Content.Headers.ContentType.MediaType == @"application/x-www-form-urlencoded")
                {
                    var content = request.Content;
                    var jsonContent = content.ReadAsStringAsync().Result;
                    return jsonContent.ParseQueryString();
                }
            }

            return result.Concat(request.RequestUri.Query.ParseQueryString()).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        public static IDictionary<string, string> ParseQueryString(this string queryString)
        {
            return HttpUtility.ParseQueryString(queryString).ToDictionary();
        }
    }
}