using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Illallangi.Extensions
{
    public static class UriExtensions
    {
        public static string GetRequest(this Uri uri)
        {
            return string.IsNullOrWhiteSpace(uri.Query) ? 
                uri.AbsoluteUri : 
                uri.AbsoluteUri.Replace(uri.Query, string.Empty);
        }
    }
}
