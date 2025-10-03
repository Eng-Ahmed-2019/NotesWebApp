using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace NotesJwtApi.Models
{
    public class Note
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Title { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Content { get; set; }

        public DateTime CreatedAt { set; get; } = DateTime.UtcNow;

        [ScaffoldColumn(false)]
        //[JsonIgnore]
        public string? UserId { set; get; }
        [ForeignKey(nameof(UserId))]
        public ApplicationUser? User { get; set; }
    }
}