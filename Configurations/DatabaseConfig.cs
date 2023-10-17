namespace SecureAPI.Configurations
{
    public class DatabaseConfig
    {
        public int? TimeoutTime { get; set; } = null;

        public bool DetailedError { get; set; }

        public bool SensitiveDataLogging { get; set; }
    }
}