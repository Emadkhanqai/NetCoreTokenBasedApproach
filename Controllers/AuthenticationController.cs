using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NetCoreTokenBasedApproach.Data;
using NetCoreTokenBasedApproach.Data.Helpers;
using NetCoreTokenBasedApproach.Data.Models;
using NetCoreTokenBasedApproach.Data.ViewModels;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace NetCoreTokenBasedApproach.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly AppDbContext _context;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly TokenValidationParameters _tokenValidationParameters;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthenticationController(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        AppDbContext context,
        IConfiguration configuration,
        TokenValidationParameters tokenValidationParameters)
    {
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
        _tokenValidationParameters = tokenValidationParameters;
    }

    [HttpPost("register-user")]
    public async Task<ActionResult> Register([FromBody] RegisterVM registerVm)
    {
        try
        {
            if (!ModelState.IsValid) return BadRequest("Please fill required fields");

            var userExists = await _userManager.FindByEmailAsync(registerVm.EmailAddress);

            if (userExists != null) return BadRequest($"User {registerVm.EmailAddress} already exists");

            var newUser = new ApplicationUser
            {
                FirstName = registerVm.FirstName,
                LastName = registerVm.LastName,
                Email = registerVm.EmailAddress,
                UserName = registerVm.UserName,
                Custom = "",
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(newUser, registerVm.Password);

            if (result.Succeeded)
            {
                // Add User Role
                switch (registerVm.Role)
                {
                    case UserRoles.Manager:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Manager);
                        break;
                    case UserRoles.Student:
                        await _userManager.AddToRoleAsync(newUser, UserRoles.Student); 
                        break;
                    default:
                            break;
                }

                return Ok("User Created");
            }
            return BadRequest("User not created");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("login-user")]
    public async Task<IActionResult> Login([FromBody] LoginVM loginVm)
    {
        if (!ModelState.IsValid) return BadRequest("Please provide all valid fields");

        var userExists = await _userManager.FindByEmailAsync(loginVm.EmailAddress);

        if (userExists != null && await _userManager.CheckPasswordAsync(userExists, loginVm.Password))
        {
            var tokenValue = await GenerateJwtTokenAsync(userExists, null);
            return Ok(tokenValue);
        }

        return Unauthorized("Wrong credentials");
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequestVM tokenRequestVm)
    {
        if (!ModelState.IsValid) return BadRequest("Please provide all valid fields");

        var result = await VerifyAndGenerateTokenAsync(tokenRequestVm);
        return Ok(result);
    }

    private async Task<AuthResultVM> VerifyAndGenerateTokenAsync(TokenRequestVM tokenRequestVm)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var storedToken =
            await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequestVm.RefreshToken);

        var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

        try
        {
            var tokenCheckResult = jwtTokenHandler.ValidateToken(
                tokenRequestVm.Token,
                _tokenValidationParameters,
                out var validatedToken);

            return await GenerateJwtTokenAsync(dbUser, storedToken);
        }
        catch (SecurityTokenExpiredException)
        {
            if (storedToken.DateExpire >= DateTime.UtcNow)
                return await GenerateJwtTokenAsync(dbUser, storedToken);
            return await GenerateJwtTokenAsync(dbUser, null);
        }
    }

    private async Task<AuthResultVM> GenerateJwtTokenAsync(ApplicationUser user, RefreshToken rToken)
    {
        var authClaims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Sub, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Add User Role Claims
        var userRoles = await _userManager.GetRolesAsync(user);
        foreach (var userRole in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        }


        var authSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["JWT:Secret"]));

        var token = new JwtSecurityToken(
            _configuration["JWT:Issuer"],
            _configuration["JWT:Audience"],
            expires: DateTime.UtcNow.AddMinutes(1),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

        var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

        // Store Refresh Token
        if (rToken != null)
            return new AuthResultVM
            {
                Token = jwtToken,
                ExpiresAt = token.ValidTo,
                RefreshToken = rToken.Token
            };

        var refreshToken = new RefreshToken
        {
            JwtId = token.Id,
            IsRevoked = false,
            UserId = user.Id,
            DateAdded = DateTime.UtcNow,
            DateExpire = DateTime.UtcNow.AddMonths(6),
            Token = Guid.NewGuid() + "-" + Guid.NewGuid()
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();

        var response = new AuthResultVM
        {
            Token = jwtToken,
            ExpiresAt = token.ValidTo,
            RefreshToken = refreshToken.Token
        };

        return response;
    }
}