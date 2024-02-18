using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NetCoreTokenBasedApproach.Data.Models;

namespace NetCoreTokenBasedApproach.Data
{
    public class AppDbContext: IdentityDbContext<ApplicationUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options): base(options)
        {
            
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }

    }
}
