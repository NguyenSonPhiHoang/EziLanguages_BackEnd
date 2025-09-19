namespace EziLanguages.Model
{
    public class OtpVerification
    {
        public int OTPId { get; set; }
        public int UserId { get; set; }
        public string OTPCode { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; }
        public string Purpose { get; set; } = string.Empty; // "Register", "ForgotPassword"
        public DateTime CreatedAt { get; set; }
    }
}
