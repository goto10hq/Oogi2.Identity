using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Oogi2.Attributes;

namespace Oogi2.Identity.CoreWeb.Models
{
    [EntityType("entity", "oogi2.identity.web")]
    public class ApplicationUser : IdentityUser
    {
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }
}