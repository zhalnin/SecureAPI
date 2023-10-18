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
using SecureAPI.Data;
using Microsoft.EntityFrameworkCore;

namespace SecureAPI.Controllers;

[Route("api/[controller]")]// api/authentication
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtConfig _jwtConfig;
    private readonly AppDbContext _appDbContext;
    private readonly TokenValidationParameters _tokenValidationParameters;

    public AuthenticationController(
        UserManager<IdentityUser> userManager,
        IOptions<JwtConfig> jwtConfig,
        AppDbContext appDbContext,
        TokenValidationParameters tokenValidationParameters)
    {
        _userManager = userManager;
        _jwtConfig = jwtConfig.Value;
        _appDbContext=appDbContext;
        _tokenValidationParameters=tokenValidationParameters;
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
                var result = await GenerateJwtToken(new_user);
                return Ok(result);
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

            var result = await GenerateJwtToken(existing_user);
            return Ok(result);
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

    private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
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

            Expires = DateTime.UtcNow.Add(_jwtConfig.ExpiryTimeFrame),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);

        var refreshToken = new RefreshToken
        {
            JwtId = token.Id,
            Token = RandomStringGeneration(23), // Generate a refresh token
            AddedDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddMonths(6),
            IsRevoked = false,
            IsUsed = false,
            UserId = user.Id
        };

        await _appDbContext.RefreshTokens.AddAsync(refreshToken);
        await _appDbContext.SaveChangesAsync();

        return new AuthResult
        {
            Result = true,
            RefreshToken = refreshToken.Token,
            Token = jwtToken
        };
    }

    [HttpPost]
    [Route("RefreshToken")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
    {
        if (ModelState.IsValid)
        {
            var result = await VerifyAndGenerateToken(tokenRequest);

            if(result is null)
            {
                return BadRequest(new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invalid token"
                    },
                    Result = false
                });
            }
            return Ok(result);
        }

        return BadRequest(new AuthResult
        {
            Errors = new List<string>
            {
                "Invalid parameters"
            },
            Result = false
        });
    }

    private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        try
        {
            _tokenValidationParameters.ValidateLifetime = false; // false - for testing purposes

            var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);
            if(validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                if(!result)
                {
                    return null;
                }
            }

            var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

            var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

            if (expiryDate > DateTime.Now)
            {
                return new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Expired token"
                    },
                    Result = false,
                };
            }

            var storedToken = await _appDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token.Equals(tokenRequest.RefreshToken));
            if (storedToken is null)
            {
                return new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invalid tokens"
                    },
                    Result = false
                };
            }

            if(storedToken.IsUsed)
            {
                return new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invalid tokens"
                    },
                    Result = false
                };
            }

            if(storedToken.IsRevoked)
            {
                return new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invalid tokens"
                    },
                    Result = false
                };
            }

            var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            if(storedToken.JwtId != jti)
            {
                return new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Invalid tokens"
                    },
                    Result = false
                };
            }

            if(storedToken.ExpiryDate < DateTime.UtcNow)
            {
                return new AuthResult
                {
                    Errors = new List<string>
                    {
                        "Expired tokens"
                    },
                    Result = false
                };
            }

            storedToken.IsUsed = true;
            _appDbContext.RefreshTokens.Update(storedToken);
            await _appDbContext.SaveChangesAsync();

            var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
            return await GenerateJwtToken(dbUser);
        }
        catch(Exception ex)
        {
            return new AuthResult
            {
                Errors = new List<string>
                    {
                        "Server error"
                    },
                Result = false
            };
        }
    }

    private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
    {
        var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
        return dateTimeVal;
    }

    private string RandomStringGeneration(int length)
    {
        var random = new Random();
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqurstuvwxyz_";
        return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
    }
}