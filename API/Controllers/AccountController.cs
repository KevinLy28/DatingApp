using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController : BaseAPIController
{
    private readonly DataContext _context;
    private readonly ITokenService _tokenService;

    public AccountController(DataContext context, ITokenService tokenService)
    {
        _tokenService = tokenService;
        _context = context;
    }

    [HttpPost("register")] //POST: api/account/register, https://localhost:5001/api/account/register?username=Kev&password=dsa
    public async Task<ActionResult<UserDto>> Register(RegisterDtos registerDtos)
    {
        if (await UserExists(registerDtos.Username)) return BadRequest("Username is taken");

        using var hmac = new HMACSHA512();

        var user = new AppUser
        {
            UserName = registerDtos.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDtos.Password)),
            PasswordSalt = hmac.Key
        };

        _context.User.Add(user);
        await _context.SaveChangesAsync();

        return new UserDto
        {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user),
        };
    } 

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDtos loginDto)
    {
        var user = await _context.User
        .Include(p => p.Photos)
        .SingleOrDefaultAsync(x =>
        x.UserName == loginDto.Username);

        if (user == null) return Unauthorized("invalid username");

        using var hmac = new HMACSHA512(user.PasswordSalt);

        var computedHash =  hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("incorrect password");
        }

        return new UserDto
        {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user),
            PhotoUrl = user.Photos.FirstOrDefault(x => x.IsMain)?.Url
        };
    }


    private async Task<bool> UserExists(string username)
    {
        return await _context.User.AnyAsync(x => x.UserName == username.ToLower());
    }
}
