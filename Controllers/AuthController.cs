using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using EziLanguages.Services;
using EziLanguages.Model;
using EziLanguages.Utilities;

namespace EziLanguages.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        private readonly IEmailRepository _emailRepository;
        private readonly IConfiguration _configuration;

        public AuthController(IAuthRepository authRepository, IEmailRepository emailRepository, IConfiguration configuration)
        {
            _authRepository = authRepository;
            _emailRepository = emailRepository;
            _configuration = configuration;
        }

        /// <summary>
        /// Đăng ký tài khoản (chưa kích hoạt, cần OTP)
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingUser = await _authRepository.GetUserByEmailAsync(request.Email);
            if (existingUser != null)
                return BadRequest(ApiResponse<string>.ErrorResponse("Email already exists."));

            string passwordHash = PasswordHasher.HashPassword(request.Password);
            int userId = await _authRepository.RegisterAsync(request, passwordHash);

            // Tạo OTP
            string otpCode = new Random().Next(100000, 999999).ToString();

            // Lưu OTP (5 phút mặc định)
            await _authRepository.SaveOtpAsync(userId, otpCode, "Register", 5);

            // Gửi email
            await _emailRepository.SendEmailAsync(request.Email, "OTP Verification",
                $"Your OTP code is: {otpCode}. It will expire in 5 minutes.");

            return Ok(ApiResponse<string>.SuccessResponse("Registered successfully. Please check your email for OTP verification."));
        }

        /// <summary>
        /// Xác thực OTP để kích hoạt tài khoản
        /// </summary>
        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpVerificationRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var otp = await _authRepository.GetOtpAsync(request.Email, request.OtpCode, "Register");

            if (otp == null || otp.IsUsed || otp.ExpiresAt < DateTime.UtcNow)
                return BadRequest(ApiResponse<string>.ErrorResponse("Invalid or expired OTP."));

            await _authRepository.MarkOtpAsUsedAsync(otp.OTPId);
            await _authRepository.ActivateUserAsync(otp.UserId);

            return Ok(ApiResponse<string>.SuccessResponse("Account activated successfully."));
        }

        /// <summary>
        /// Đăng nhập (JWT Token)
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _authRepository.GetUserByEmailAsync(request.Email);
            if (user == null || !PasswordHasher.VerifyPassword(request.Password, user.PasswordHash))
                return Unauthorized(ApiResponse<string>.ErrorResponse("Invalid email or password."));

            if (!user.IsActive)
                return Unauthorized(ApiResponse<string>.ErrorResponse("Account not activated. Please verify your email."));

            string token = GenerateJwtToken(user);

            return Ok(ApiResponse<object>.SuccessResponse(new
            {
                Token = token,
                User = new
                {
                    user.UserId,
                    user.FullName,
                    user.Email,
                    user.RoleId
                }
            }, "Login successful."));
        }

        /// <summary>
        /// Gửi lại OTP khi chưa kích hoạt
        /// </summary>
        [HttpPost("resend-otp")]
        public async Task<IActionResult> ResendOtp([FromBody] OtpResendRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _authRepository.GetUserByEmailAsync(request.Email);
            if (user == null)
                return NotFound(ApiResponse<string>.ErrorResponse("User not found."));

            if (user.IsActive)
                return BadRequest(ApiResponse<string>.ErrorResponse("Account is already activated."));

            string otpCode = new Random().Next(100000, 999999).ToString();

            // Lưu OTP mới (5 phút mặc định)
            await _authRepository.SaveOtpAsync(user.UserId, otpCode, "Register", 5);

            await _emailRepository.SendEmailAsync(user.Email, "OTP Verification",
                $"Your new OTP code is: {otpCode}. It will expire in 5 minutes.");

            return Ok(ApiResponse<string>.SuccessResponse("OTP resent successfully. Please check your email."));
        }

        // JWT Generate
        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("FullName", user.FullName),
                new Claim("RoleId", user.RoleId.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(2),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
