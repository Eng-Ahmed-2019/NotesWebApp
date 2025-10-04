using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NotesJwtApi.Models;

namespace NotesJwtApi.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }

        public DbSet<Note> Notes { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<RevokedToken> RevokedTokens { get; set; }
    }
}