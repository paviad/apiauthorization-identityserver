// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using ApiAuthorization.IdentityServer.Configuration;
using ApiAuthorization.IdentityServer.Options;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace ApiAuthorization.IdentityServer.Extensions;

internal sealed class DefaultClientRequestParametersProvider(
    IAbsoluteUrlFactory urlFactory,
    IIssuerNameService issuerNameService,
    IOptions<ApiAuthorizationOptions> options)
    : IClientRequestParametersProvider {
    public IAbsoluteUrlFactory UrlFactory { get; } = urlFactory;

    public IOptions<ApiAuthorizationOptions> Options { get; } = options;

    public IDictionary<string, string?> GetClientParameters(HttpContext context, string? clientId) {
        var awaiter = GetClientParametersAsync(context, clientId);
        awaiter.Wait();
        return awaiter.Result;
    }

    public async Task<IDictionary<string, string?>> GetClientParametersAsync(HttpContext context, string? clientId) {
        var client = Options.Value.Clients[clientId];
        // Deprecated in Identity Server 6.0
        var authority = await issuerNameService.GetCurrentAsync();
        if (!client.Properties.TryGetValue(ApplicationProfilesPropertyNames.Profile, out var type)) {
            throw new InvalidOperationException($"Can't determine the type for the client '{clientId}'");
        }

        var responseType = type switch {
            ApplicationProfiles.IdentityServerSpa or
                ApplicationProfiles.Spa or
                ApplicationProfiles.NativeApp => "code",
            _ => throw new InvalidOperationException($"Invalid application type '{type}' for '{clientId}'."),
        };

        return new Dictionary<string, string?> {
            ["authority"] = authority,
            ["client_id"] = client.ClientId,
            ["redirect_uri"] = UrlFactory.GetAbsoluteUrl(context, client.RedirectUris.First()),
            ["post_logout_redirect_uri"] = UrlFactory.GetAbsoluteUrl(context, client.PostLogoutRedirectUris.First()),
            ["response_type"] = responseType,
            ["scope"] = string.Join(" ", client.AllowedScopes),
        };
    }
}
