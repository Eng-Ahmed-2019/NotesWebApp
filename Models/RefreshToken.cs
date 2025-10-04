using System.ComponentModel.DataAnnotations;

namespace NotesJwtApi.Models
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Token { set; get; } = string.Empty;

        public string UserId { get; set; } = string.Empty;

        public DateTime Expires { set; get; }

        public bool IsExpired => DateTime.UtcNow >= Expires;

        public DateTime CrearedAt { set; get; } = DateTime.UtcNow;

        public DateTime? Revoked { set; get; }

        public bool isActive => Revoked == null && !IsExpired;
    }
}