using NotesJwtApi.Data;
using NotesJwtApi.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace NotesJwtApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class NotesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public NotesController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("public")]
        [AllowAnonymous]
        public async Task<IActionResult> GetPublic()
        {
            var publicNotes = await _context.Notes
                .Where(n => n.UserId == null)
                .Include(n => n.User)
                .ToListAsync();

            return Ok(publicNotes);
        }

        [HttpGet("my")]
        [Authorize]
        public async Task<IActionResult> GetMyNotes()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var notes = await _context.Notes
                .Where(n => n.UserId == userId)
                .Include(n => n.User)
                .ToListAsync();

            return Ok(notes);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CreateNote([FromBody] Note note)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            note.UserId = userId;

            _context.Notes.Add(note);
            await _context.SaveChangesAsync();

            return Ok(note);
        }

        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> EditNote(int id, [FromBody] Note updatedNote)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var note = await _context.Notes.FindAsync(id);

            if (note == null)
                return NotFound(new { message = "Note not found" });

            note.Title = updatedNote.Title;
            note.Content=updatedNote.Content;

            _context.Notes.Update(note);
            await _context.SaveChangesAsync();

            return Ok(note);
        }

        [HttpDelete("{id}")]
        [Authorize]
        public async Task<IActionResult>DeleteNote(int id)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var note = await _context.Notes.FindAsync(id);

            if (note == null)
                return NotFound(new { message = "Note not found" });

            if (note.UserId != userId)
                return Forbid();

            _context.Notes.Remove(note);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Note deleted successfully" });
        }
    }
}