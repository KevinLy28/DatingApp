using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController : BaseAPIController
{
    private readonly DataContext _context;

    public AccountController(DataContext context)
    {
        _context = context;
    }

    [HttpPost("register")] //POST: api/account/register, https://localhost:5001/api/account/register?username=Kev&password=dsa
    public async Task<ActionResult<AppUser>> Register(RegisterDtos registerDtos)
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

        return user;
    } 

    private async Task<bool> UserExists(string username)
    {
        return await _context.User.AnyAsync(x => x.UserName == username.ToLower());
    }
}
