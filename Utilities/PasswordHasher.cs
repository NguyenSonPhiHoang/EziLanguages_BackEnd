using System.Security.Cryptography;
using System.Text;

namespace EziLanguages.Utilities
{
    public static class PasswordHasher
    {
        // Mã hóa mật khẩu sử dụng SHA256
        public static string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(password);
                byte[] hash = sha256.ComputeHash(bytes);

                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < hash.Length; i++)
                {
                    builder.Append(hash[i].ToString("x2"));
                }

                return builder.ToString();
            }
        }

        // Xác minh mật khẩu
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            string hashedInput = HashPassword(password);
            return hashedInput.Equals(hashedPassword);
        }
    }
}