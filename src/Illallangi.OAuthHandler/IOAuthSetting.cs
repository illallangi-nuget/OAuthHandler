namespace Illallangi
{
    public interface IOAuthSetting
    {
        string ConsumerKey { get; set; }
        string ConsumerSecret { get; set; }
        string AuthorizedKey { get; set; }
        string AuthorizedSecret { get; set; }
        string BaseUrl { get; set; }
        string AuthorizeUrl { get; set; }
        string CallBackUrl { get; set; }
    }
}