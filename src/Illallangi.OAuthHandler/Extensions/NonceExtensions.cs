using System.Security.Cryptography;
using System.Text;

namespace Illallangi.Extensions
{
    public static class NonceExtensions
    {
        public static string GenerateNonce(this OAuthHmacSha1Handler handler)
        {
            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

            var data = new byte[1];
            using (var crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[handler.NonceLength];
                crypto.GetNonZeroBytes(data);
            }

            var result = new StringBuilder(handler.NonceLength);
            foreach (var b in data)
            {
                result.Append(chars[b % chars.Length]);
            }

            return result.ToString();
        }
    }
}
