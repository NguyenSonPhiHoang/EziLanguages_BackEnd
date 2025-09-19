using System;

namespace EziLanguages.Model
{
    public class User
    {
        public int UserId { get; set; }          // Khóa chính
        public string FullName { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string PasswordHash { get; set; } = null!;
        public int Age { get; set; }
        public int RoleId { get; set; }          // 1=Admin, 2=Student, 3=Teacher
        public bool IsActive { get; set; }       // Mới thêm
        public DateTime CreatedAt { get; set; }  // Ngày tạo
        public DateTime? UpdatedAt { get; set; } // Ngày cập nhật (nullable)
    }
}
