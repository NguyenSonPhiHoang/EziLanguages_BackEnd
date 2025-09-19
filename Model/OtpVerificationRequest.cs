using System.ComponentModel.DataAnnotations;

namespace EziLanguages.Model
{
    public class OtpVerificationRequest
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;

        [Required(ErrorMessage = "OTP code is required")]
        [StringLength(6, MinimumLength = 4, ErrorMessage = "OTP code must be 4–6 digits")]
        public string OtpCode { get; set; } = null!;
    }
}
