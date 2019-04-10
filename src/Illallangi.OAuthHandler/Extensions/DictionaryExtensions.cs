using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Runtime.Serialization;
using Illallangi.Extensions;

namespace Illallangi
{
    public static class DictionaryExtensions
    {
        public static IDictionary<string, IEnumerable<string>> ReplacePlaceholders(
            this IDictionary<string, IEnumerable<string>> inp,
            IDictionary<string, KeyValuePair<string, string>> placeholders)
        {
            foreach (var placeholder in placeholders.Values)
            {
                inp = inp?.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Select(v => v.Replace(placeholder.Key, Uri.EscapeDataString(placeholder.Value))));
            }

            return inp;
        }
    }
}