using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using WebApplication1.Models;
using WebApplication1.Providers;

namespace WebApplication1
{
    public partial class Startup
    {
        static Startup()
        {
            PublicClientId = "web";

            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/Token"),
                AuthorizeEndpointPath = new PathString("/Account/Authorize"),
                Provider = new ApplicationOAuthProvider(PublicClientId),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true
            };
        }

        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        public static string PublicClientId { get; private set; }

        public void ConfigureAuth(IAppBuilder app)
        {
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                      
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(20),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            app.UseOAuthBearerTokens(OAuthOptions);
            
            app.UseMicrosoftAccountAuthentication(
                clientId: "6396c4ed-e5fa-4526-9133-b6e2fd3dfce4",
                clientSecret: "Enter Secret Key");

            app.UseTwitterAuthentication(
                consumerKey: "",
                consumerSecret: "");

            app.UseFacebookAuthentication(
                appId: "2611367562516671",
                appSecret: "Enter Secret Key");

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            {
                ClientId = "17762882567-fp3oqgt2mgj3d0agto2tii88qf7ph8a9.apps.googleusercontent.com",
                ClientSecret = "Enter Secret Key"
            });
        }
    }
}
