using System.ComponentModel.DataAnnotations;

namespace JWT_Token.Data.Models.DTOs
{
    public class UserLoginRequestDto
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
