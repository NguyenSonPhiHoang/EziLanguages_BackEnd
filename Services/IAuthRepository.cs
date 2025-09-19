using EziLanguages.Model;
using EziLanguages.DataReader;
using System;
using System.Threading.Tasks;

namespace EziLanguages.Services
{
    public interface IAuthRepository
    {
        // Đăng ký
        Task<int> RegisterAsync(RegisterRequest request, string passwordHash);

        // Lưu OTP
        Task<int> SaveOtpAsync(int userId, string otpCode, string purpose, int expireMinutes = 5);

        // Lấy OTP
        Task<OTPVerification?> GetOtpAsync(string email, string otpCode, string purpose);

        // Đánh dấu OTP đã dùng
        Task<int> MarkOtpAsUsedAsync(int otpId);

        // Kích hoạt user
        Task<int> ActivateUserAsync(int userId);

        // Lấy user theo email
        Task<User?> GetUserByEmailAsync(string email);

        // Login
        Task<User?> LoginAsync(string email, string passwordHash);
    }

    public class AuthRepository : IAuthRepository
    {
        private readonly DatabaseDapper _db;

        public AuthRepository(DatabaseDapper db)
        {
            _db = db;
        }

        // Đăng ký user (IsActive = 0 mặc định)
        public async Task<int> RegisterAsync(RegisterRequest request, string passwordHash)
        {
            return await _db.ExecuteStoredProcedureAsync("sp_Auth_Register", new
            {
                request.FullName,
                request.Email,
                PasswordHash = passwordHash,
                request.Age,
                request.RoleId
            });
        }

        // Lưu OTP vào bảng OTPVerification
        public async Task<int> SaveOtpAsync(int userId, string otpCode, string purpose, int expireMinutes = 5)
        {
            return await _db.ExecuteStoredProcedureAsync("sp_Auth_SaveOtp", new
            {
                UserId = userId,
                OTPCode = otpCode,
                Purpose = purpose,
                ExpireMinutes = expireMinutes
            });
        }


        // Lấy OTP theo email + code + purpose
        public async Task<OTPVerification?> GetOtpAsync(string email, string otpCode, string purpose)
        {
            return await _db.QueryFirstOrDefaultStoredProcedureAsync<OTPVerification>("sp_Auth_GetOtp", new
            {
                Email = email,
                OTPCode = otpCode,
                Purpose = purpose
            });
        }

        // Đánh dấu OTP đã dùng
        public async Task<int> MarkOtpAsUsedAsync(int otpId)
        {
            return await _db.ExecuteStoredProcedureAsync("sp_Auth_MarkOtpUsed", new
            {
                OTPId = otpId
            });
        }

        // Kích hoạt user (IsActive = 1)
        public async Task<int> ActivateUserAsync(int userId)
        {
            return await _db.ExecuteStoredProcedureAsync("sp_Auth_ActivateUser", new
            {
                UserId = userId
            });
        }

        // Lấy user theo email
        public async Task<User?> GetUserByEmailAsync(string email)
        {
            return await _db.QueryFirstOrDefaultStoredProcedureAsync<User>("sp_Auth_GetUserByEmail", new
            {
                Email = email
            });
        }

        // Login: check email + password hash
        public async Task<User?> LoginAsync(string email, string passwordHash)
        {
            return await _db.QueryFirstOrDefaultStoredProcedureAsync<User>("sp_Auth_Login", new
            {
                Email = email,
                PasswordHash = passwordHash
            });
        }
    }
}
