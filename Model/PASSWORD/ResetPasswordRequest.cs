using System.ComponentModel.DataAnnotations;

namespace EziLanguages.Model
{
    public class ResetPasswordRequest
    {
        [Required]
        public int UserId { get; set; }

        [Required]
        public string ResetToken { get; set; } = null!;

        [Required]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
        public string NewPassword { get; set; } = null!;
    }
}
