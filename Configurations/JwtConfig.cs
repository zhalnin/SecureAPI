namespace SecureAPI.Configurations
{
    public class JwtConfig
    {
        public string Secret { get; set; } = string.Empty;
        public TimeSpan ExpiryTimeFrame { get; set; }
        public string Ssid { get; set; } = string.Empty;
    }
}