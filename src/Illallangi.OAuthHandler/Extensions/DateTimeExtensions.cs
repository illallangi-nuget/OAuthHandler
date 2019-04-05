using System;
using System.Globalization;

namespace Illallangi.Extensions
{
    public static class DateTimeExtensions
    { 
        public static string GenerateTimeStamp(this DateTime dateTime)
        {
            return Math.Truncate((dateTime.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }
    }
}