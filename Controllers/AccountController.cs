using System.Linq;
using System;
using System.Threading.Tasks;
using Demo1.Models;
using Demo1.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace Demo1.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        public AccountController(UserManager<IdentityUser> userManager)
        {
            this._userManager = userManager;
        }

        [HttpPost]
        public async Task<ResultVM> Register([FromBody]RegisterVM model)
        {
            if (ModelState.IsValid)
            {
                IdentityResult result = null;
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null)
                {
                    return new ResultVM
                    {
                        Status = Status.Error,
                        Message = "Invalid data",
                        Data = "User already exists"
                    };
                }

                user = new IdentityUser
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = model.UserName,
                    Email = model.Email
                };

                result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    return new ResultVM
                    {
                        Status = Status.Success,
                        Message = "User Created",
                        Data = user
                    };
                }
                else
                {
                    var resultErrors = result.Errors.Select(e => e.Description);
                    return new ResultVM
                    {
                        Status = Status.Error,
                        Message = "Invalid data",
                        Data = string.Join(",", resultErrors)
                    };
                }
            }
            var errors = ModelState.Keys.Select(e => e.ToString());
            return new ResultVM
            {
                Status = Status.Error,
                Message = "Invalid data",
                Data = string.Join(",", errors)
            };
        }


        [HttpPost]
        public async Task<ResultVM> Login([FromBody]LoginVM model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

                    return new ResultVM
                    {
                        Status = Status.Success,
                        Message = "Succesfull login",
                        Data = model
                    };
                }
                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = "Invalid Username or Password"
                };
            }
            var errors = ModelState.Keys.Select(e => e.ToString());
            return new ResultVM
            {
                Status = Status.Error,
                Message = "Invalid data",
                Data = string.Join(",", errors)
            };
        }


        [HttpGet]
        [Authorize]
        public async Task<UserClaims> Claims()
        {
            var claims = User.Claims.Select(c => new ClaimVM
            {
                Type = c.Type,
                Value = c.Value
            });
            return new UserClaims
            {
                UserName = User.Identity.Name,
                Claims = claims
            };
        }

        [HttpGet]
        public async Task<UserStateVM> Authenticated()
        {
            return new UserStateVM
            {
                IsAuthenticated = User.Identity.IsAuthenticated,
                Username = User.Identity.IsAuthenticated ? User.Identity.Name : string.Empty
            };
        }

        [HttpPost]
        public async Task SignOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}