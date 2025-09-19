using System.ComponentModel.DataAnnotations;

namespace EziLanguages.Model
{
    public class RegisterRequest
    {
        [Required(ErrorMessage = "Full name is required")]
        public string FullName { get; set; } = null!;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;

        [Required(ErrorMessage = "Password is required")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        public string Password { get; set; } = null!;

        [Range(1, 120, ErrorMessage = "Age must be between 1 and 120")]
        public int Age { get; set; }

        /// <summary>
        /// RoleId: 1=Admin, 2=Student, 3=Teacher (default = 2 Student)
        /// </summary>
        public int RoleId { get; set; } = 2;
    }
}
