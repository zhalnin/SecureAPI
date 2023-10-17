using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureAPI.Configurations;
using SecureAPI.Models;
using SecureAPI.Models.Dtos;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace SecureAPI.Controllers;

[Route("api/[controller]")]// api/authentication
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtConfig _jwtConfig;

    public AuthenticationController(
        UserManager<IdentityUser> userManager,
        IOptions<JwtConfig> jwtConfig,
        IOptions<DatabaseConfig> dbConfig)
    {
        _userManager = userManager;
        _jwtConfig = jwtConfig.Value;
    }

    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
    {
        if (ModelState.IsValid)
        {
            var user_exist = await _userManager.FindByEmailAsync(requestDto.Email);
            if (user_exist is not null)
            {
                return BadRequest(new AuthResult
                {
                    Result = false,
                    Errors = new List<string>
                    {
                        "Email already exists."
                    }
                });
            }

            var new_user = new IdentityUser
            {
                UserName = requestDto.Email,
                Email = requestDto.Email
            };

            var is_created = await _userManager.CreateAsync(new_user, requestDto.Password);

            if (is_created.Succeeded)
            {
                var token = GenerateJwtToken(new_user);
                return Ok(new AuthResult
                {
                    Result = true,
                    Token = token
                });
            }

            var errors = new List<string>();
            if (is_created.Errors.Count() > 0)
            {
                foreach (var item in is_created.Errors)
                {
                    errors.Add(item.Description);
                }
            }

            return BadRequest(new AuthResult
            {
                Result = false,
                Errors = errors

            });
        }
        return BadRequest();
    }

    [HttpPost]
    [Route("Login")]
    public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginRequest)
    {
        if (ModelState.IsValid)
        {
            var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);
            if (existing_user is null)
            {
                return BadRequest(new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invalid payload"
                    },
                    Result = false
                });
            }

            var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);
            if (!isCorrect)
            {
                return BadRequest(new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invlaid credentials"
                    },
                    Result = false
                });
            }

            var jwtToken = GenerateJwtToken(existing_user);
            return Ok(new AuthResult
            {
                Result = true,
                Token = jwtToken
            });
        }

        return BadRequest(new AuthResult
        {
            Errors = new List<string>
            {
                "Invalid payload"
            },
            Result = false
        });
    }

    private string GenerateJwtToken(IdentityUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret.ToString());
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
            }),

            Expires = DateTime.Now.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);
        return jwtToken;
    }
}