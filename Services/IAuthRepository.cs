using EziLanguages.Model;
using EziLanguages.DataReader;
using EziLanguages.Utilities;
using System;
using System.Threading.Tasks;

namespace EziLanguages.Services
{
    public interface IAuthRepository
    {
    Task<ApiResponse<string>> Register(RegisterRequest request);
    Task<ApiResponse<string>> VerifyOtp(OtpVerificationRequest request);
    Task<ApiResponse<object>> Login(LoginRequest request);
    Task<ApiResponse<string>> ResendOtp(OtpResendRequest request);
    Task<ApiResponse<object>> ForgotPassword(ForgotPasswordRequest request);
    Task<ApiResponse<string>> ResetPassword(ResetPasswordRequest request);
    }



        public class AuthRepository : IAuthRepository
        {
            private readonly DatabaseDapper _db;
            private readonly IEmailRepository _emailRepository;
            private readonly IConfiguration _configuration;

            public AuthRepository(DatabaseDapper db, IEmailRepository emailRepository, IConfiguration configuration)
            {
                _db = db;
                _emailRepository = emailRepository;
                _configuration = configuration;
            }

            public async Task<ApiResponse<object>> ForgotPassword(ForgotPasswordRequest request)
            {
                // Kiểm tra user tồn tại
                var user = await _db.QueryFirstOrDefaultStoredProcedureAsync<User>("sp_Auth_GetUserByEmail", new { Email = request.Email });
                if (user == null)
                    return ApiResponse<object>.ErrorResponse("Email not found.");

                // Sinh reset token
                var resetToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
                var expireAt = DateTime.UtcNow.AddMinutes(30);

                // Lưu vào bảng PasswordResetTokens (giả sử có sp_Auth_SavePasswordResetToken)
                await _db.ExecuteStoredProcedureAsync("sp_Auth_SavePasswordResetToken", new
                {
                    UserId = user.UserId,
                    ResetToken = resetToken,
                    CreatedAt = DateTime.UtcNow,
                    ExpireAt = expireAt,
                    ResetTokenUsed = false
                });

                // Gửi email (link mẫu, thực tế FE sẽ nhận link này)
                var resetLink = $"https://your-frontend/reset-password?userId={user.UserId}&resetToken={resetToken}";
                await _emailRepository.SendEmailAsync(user.Email, "Password Reset",
                    $"Click the link to reset your password: {resetLink}");

                // Trả về resetToken cho swagger test
                return ApiResponse<object>.SuccessResponse(new { user.UserId, ResetToken = resetToken }, "Reset token sent to email.");
            }

            public async Task<ApiResponse<string>> ResetPassword(ResetPasswordRequest request)
            {
                // 1. Kiểm tra token hợp lệ
                var resetToken = await _db.QueryFirstOrDefaultStoredProcedureAsync<PasswordResetToken>("sp_Auth_GetPasswordResetToken", new {
                    UserId = request.UserId,
                    ResetToken = request.ResetToken
                });
                if (resetToken == null)
                    return ApiResponse<string>.ErrorResponse("Invalid reset token.");
                if (resetToken.ResetTokenUsed)
                    return ApiResponse<string>.ErrorResponse("Reset token already used.");
                if (resetToken.ExpireAt < DateTime.UtcNow)
                    return ApiResponse<string>.ErrorResponse("Reset token expired.");

                // 2. Đổi mật khẩu
                string newPasswordHash = PasswordHasher.HashPassword(request.NewPassword);
                await _db.ExecuteStoredProcedureAsync("sp_Auth_UpdateUserPassword", new {
                    UserId = request.UserId,
                    PasswordHash = newPasswordHash
                });

                // 3. Đánh dấu token đã dùng
                await _db.ExecuteStoredProcedureAsync("sp_Auth_MarkPasswordResetTokenUsed", new {
                    TokenId = resetToken.TokenId
                });

                return ApiResponse<string>.SuccessResponse("Password reset successfully.");
            }

            // ...existing methods Register, VerifyOtp, Login, ResendOtp...

        public async Task<ApiResponse<string>> Register(RegisterRequest request)
        {
            var existingUser = await _db.QueryFirstOrDefaultStoredProcedureAsync<User>("sp_Auth_GetUserByEmail", new { Email = request.Email });
            if (existingUser != null)
                return ApiResponse<string>.ErrorResponse("Email already exists.");

            string passwordHash = PasswordHasher.HashPassword(request.Password);
            int userId = await _db.ExecuteStoredProcedureAsync("sp_Auth_Register", new
            {
                request.FullName,
                request.Email,
                PasswordHash = passwordHash,
                request.Age,
                request.RoleId
            });
            if (userId <= 0)
                return ApiResponse<string>.ErrorResponse("Register failed.");

            string otpCode = new Random().Next(100000, 999999).ToString();
            await _db.ExecuteStoredProcedureAsync("sp_Auth_SaveOtp", new
            {
                UserId = userId,
                OTPCode = otpCode,
                Purpose = "Register",
                ExpireMinutes = 5
            });

            // Gửi email OTP
            await _emailRepository.SendEmailAsync(request.Email, "OTP Verification",
                $"Your OTP code is: {otpCode}. It will expire in 5 minutes.");

            return ApiResponse<string>.SuccessResponse("Registered successfully. Please check your email for OTP verification.");
        }

    public async Task<ApiResponse<string>> VerifyOtp(OtpVerificationRequest request)
        {
            var otp = await _db.QueryFirstOrDefaultStoredProcedureAsync<OtpVerification>("sp_Auth_GetOtp", new
            {
                Email = request.Email,
                OTPCode = request.OtpCode,
                Purpose = "Register"
            });

            if (otp == null || otp.IsUsed || otp.ExpiresAt < DateTime.UtcNow)
                return ApiResponse<string>.ErrorResponse("Invalid or expired OTP.");

            await _db.ExecuteStoredProcedureAsync("sp_Auth_MarkOtpUsed", new { OTPId = otp.OTPId });
            await _db.ExecuteStoredProcedureAsync("sp_Auth_ActivateUser", new { UserId = otp.UserId });

            return ApiResponse<string>.SuccessResponse("Account activated successfully.");
        }

        public async Task<ApiResponse<object>> Login(LoginRequest request)
        {
            var user = await _db.QueryFirstOrDefaultStoredProcedureAsync<User>("sp_Auth_GetUserByEmail", new { Email = request.Email });
            if (user == null || !PasswordHasher.VerifyPassword(request.Password, user.PasswordHash))
                return ApiResponse<object>.ErrorResponse("Invalid email or password.");

            if (!user.IsActive)
                return ApiResponse<object>.ErrorResponse("Account not activated. Please verify your email.");

            // Sinh access token
            var claims = new[]
            {
                new System.Security.Claims.Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new System.Security.Claims.Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email, user.Email),
                new System.Security.Claims.Claim("FullName", user.FullName),
                new System.Security.Claims.Claim("RoleId", user.RoleId.ToString())
            };
            var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(key, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
            var expires = DateTime.UtcNow.AddHours(2);
            var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );
            var accessToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);

            // Sinh refresh token
            var refreshToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            var refreshTokenExpire = DateTime.UtcNow.AddDays(7);

            // Lưu vào bảng Tokens (giả sử có stored procedure sp_Auth_SaveToken)
            await _db.ExecuteStoredProcedureAsync("sp_Auth_SaveToken", new
            {
                UserId = user.UserId,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = expires,
                IsRevoked = false
            });

            return ApiResponse<object>.SuccessResponse(new
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                User = new
                {
                    user.UserId,
                    user.FullName,
                    user.Email,
                    user.RoleId
                }
            }, "Login successful.");
        }

    public async Task<ApiResponse<string>> ResendOtp(OtpResendRequest request)
        {
            var user = await _db.QueryFirstOrDefaultStoredProcedureAsync<User>("sp_Auth_GetUserByEmail", new { Email = request.Email });
            if (user == null)
                return ApiResponse<string>.ErrorResponse("User not found.");

            if (user.IsActive)
                return ApiResponse<string>.ErrorResponse("Account is already activated.");

            // Đánh dấu tất cả OTP cũ (Register, chưa dùng) là đã dùng bằng stored procedure
            await _db.ExecuteStoredProcedureAsync("sp_Auth_MarkAllOtpUsed", new { UserId = user.UserId, Purpose = "Register" });

            string otpCode = new Random().Next(100000, 999999).ToString();
            await _db.ExecuteStoredProcedureAsync("sp_Auth_SaveOtp", new
            {
                UserId = user.UserId,
                OTPCode = otpCode,
                Purpose = "Register",
                ExpireMinutes = 5
            });
            return ApiResponse<string>.SuccessResponse("OTP resent successfully. Please check your email.");
        }
    }
}
