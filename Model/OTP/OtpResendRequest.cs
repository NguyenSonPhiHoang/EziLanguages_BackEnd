using System.ComponentModel.DataAnnotations;

namespace EziLanguages.Model
{
    public class OtpResendRequest
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;
    }
}
