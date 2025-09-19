using System;

namespace EziLanguages.Model
{
    public class PasswordResetToken
    {
        public int TokenId { get; set; }
        public int UserId { get; set; }
        public string ResetToken { get; set; } = null!;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpireAt { get; set; }
        public bool ResetTokenUsed { get; set; }
    }
}
