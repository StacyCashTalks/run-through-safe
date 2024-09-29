using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace StaticWebAppAuthentication.Client
{
    public class StaticWebAppsAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly HttpClient _http;

        public StaticWebAppsAuthenticationStateProvider(HttpClient httpClient)
        {
			_http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
			try
            {
                var clientPrincipal = await GetClientPrinciple();
                var claimsPrincipal = GetClaimsFromClientClaimsPrincipal(clientPrincipal);
                return new AuthenticationState(claimsPrincipal);
            }
            catch
            {
                return new AuthenticationState(new ClaimsPrincipal());
            }
        }

        private async Task<ClientPrincipal> GetClientPrinciple()
        {
			var data = await _http.GetFromJsonAsync<AuthenticationData>("/.auth/me");
            var clientPrincipal = data?.ClientPrincipal ?? new ClientPrincipal();
			return clientPrincipal;
        }

        private static ClaimsPrincipal GetClaimsFromClientClaimsPrincipal(ClientPrincipal principal)
        {
 			principal.UserRoles =
                principal.UserRoles?.Except(new[] { "anonymous" }, StringComparer.CurrentCultureIgnoreCase) ?? new List<string>();

 			if (!principal.UserRoles.Any())
            {
                return new ClaimsPrincipal();
            }

 			var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
		    {
				new Claim(ClaimTypes.NameIdentifier, principal.UserId),
				new Claim(ClaimTypes.Name, principal.UserDetails),
		    }, principal.IdentityProvider));

            claimsPrincipal.Identities.First().AddClaims(principal.UserRoles.Select(r => new Claim(ClaimTypes.Role, r)));

			return new ClaimsPrincipal(claimsPrincipal);

        }
    }
}
