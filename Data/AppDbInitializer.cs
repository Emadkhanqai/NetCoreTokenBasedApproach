using Microsoft.AspNetCore.Identity;
using NetCoreTokenBasedApproach.Data.Helpers;

namespace NetCoreTokenBasedApproach.Data
{
    public class AppDbInitializer
    {
        public static async Task SeedRolesToDb(IApplicationBuilder builder)
        {
            using (var serviceScope = builder.ApplicationServices.CreateScope())
            {
                var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                if (!await roleManager.RoleExistsAsync(UserRoles.Manager))
                {
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.Manager));
                }

                if (!await roleManager.RoleExistsAsync(UserRoles.Student))
                {
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.Student));
                }
            }
        }
    }
}
