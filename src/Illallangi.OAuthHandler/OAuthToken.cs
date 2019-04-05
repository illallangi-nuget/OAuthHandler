using Illallangi.Extensions;

namespace Illallangi
{
    public sealed class OAuthToken
    {
        public OAuthToken(string key, string secret)
        {
            Key = key;
            Secret = secret;
        }

        public static OAuthToken FromQueryString(string queryString)
        {
            var result = queryString.ParseQueryString();
            return new OAuthToken(result["oauth_token"], result["oauth_token_secret"]);
        }

        public string Key { get; }
        public string Secret { get; }

        public override string ToString()
        {
            return $"oauth_token={Key}&oauth_token_secret={Secret}";
        }
    }
}