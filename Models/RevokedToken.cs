using System.ComponentModel.DataAnnotations;

namespace NotesJwtApi.Models
{
    public class RevokedToken
    {
        [Key]
        public int Id { get; set; }

        public string Token { get; set; } = string.Empty;

        public DateTime RevokedAt { get; set; }
    }
}