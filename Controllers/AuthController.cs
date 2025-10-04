using System.Text;
using NotesJwtApi.Data;
using NotesJwtApi.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace NotesJwtApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration, ApplicationDbContext context)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded) return BadRequest(result.Errors);

            return Ok(new { message = "Registered successfully" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null) return Unauthorized(new { message = "Invalid credentials" });

            var check = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!check.Succeeded) return Unauthorized(new { message = "Invalid credentials" });

            var accessToken = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            var rt = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                Expires = DateTime.UtcNow.AddDays(7)
            };

            _context.RefreshTokens.Add(rt);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                accessToken,
                refreshToken
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] string refreshToken)
        {
            var storedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == refreshToken);

            if (storedToken == null || !storedToken.isActive)
                return Unauthorized(new { message = "Invalid refresh token" });

            var user = await _userManager.FindByIdAsync(storedToken.UserId);
            if (user == null) return Unauthorized();

            storedToken.Revoked = DateTime.UtcNow;

            var newRefreshToken = GenerateRefreshToken();

            var rt = new RefreshToken
            {
                Token = newRefreshToken,
                UserId = user.Id,
                Expires = DateTime.UtcNow.AddDays(7)
            };

            _context.RefreshTokens.Add(rt);

            var accessToken = GenerateJwtToken(user);

            await _context.SaveChangesAsync();

            return Ok(new
            {
                accessToken,
                refreshToken = newRefreshToken
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] string refreshToken)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var storedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == refreshToken && t.UserId == userId);

            if (storedToken == null)
                return NotFound(new { message = "Refresh token not found" });

            storedToken.Revoked = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return Ok(new { message = "Logged out successfully" });
        }

        [HttpPost("logoutall")]
        [Authorize]
        public async Task<IActionResult> LogoutAllSession()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var userTokens = await _context.RefreshTokens
                .Where(t => t.UserId == userId && t.Revoked == null && t.Expires > DateTime.UtcNow)
                .ToListAsync();

            foreach (var token in userTokens)
                token.Revoked = DateTime.UtcNow;

            var currentAccessToken = HttpContext.Request.Headers["Authorization"]
                .ToString().Replace("Bearer ", "");

            _context.RevokedTokens.Add(new RevokedToken
            {
                Token = currentAccessToken,
                RevokedAt = DateTime.UtcNow
            });

            await _context.SaveChangesAsync();

            return Ok(new { message = "Logged out successfully. All tokens revoked." });
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var jwtSection = _configuration.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Id),
                new Claim(JwtRegisteredClaimNames.UniqueName,user.UserName??""),
                new Claim(JwtRegisteredClaimNames.Email,user.Email??""),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name,user.UserName??"")
            };

            var expires = DateTime.UtcNow.AddMinutes(double.Parse(jwtSection["DurationInMinutes"]));

            var token = new JwtSecurityToken(
                issuer: jwtSection["Issuer"],
                audience: jwtSection["Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}