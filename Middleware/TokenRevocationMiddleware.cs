using NotesJwtApi.Data;

namespace NotesJwtApi.Middleware
{
    public class TokenRevocationMiddleware
    {
        private readonly RequestDelegate _next;

        public TokenRevocationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var dbContext = context.RequestServices.GetRequiredService<ApplicationDbContext>();

            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();

                var isRevoked = dbContext.RevokedTokens.Any(t => t.Token == token);

                if (isRevoked)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("This token has been revoked. Please login again.");
                    return;
                }
            }

            await _next(context);
        }
    }
}