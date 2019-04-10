using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;

namespace Illallangi.Extensions
{
    public static class NameValueCollectionExtensions
    {
        public static IDictionary<string, IEnumerable<string>> ToDictionary(this NameValueCollection nameValueCollection)
        {
            return nameValueCollection?.Cast<string>()
                .Select(s => new {Key = s, Value = (IEnumerable<string>)new List<string> {nameValueCollection[s]}})
                .ToDictionary(p => p.Key, p => p.Value);
        }
    }
}