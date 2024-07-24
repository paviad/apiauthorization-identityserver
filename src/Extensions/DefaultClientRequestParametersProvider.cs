// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
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

    public IDictionary<string, string> GetClientParameters(HttpContext context, string clientId) {
        var client = Options.Value.Clients[clientId];
        // Deprecated in Identity Server 6.0
        var authorityAwaiter = issuerNameService.GetCurrentAsync();
        authorityAwaiter.Wait();
        var authority = authorityAwaiter.Result; //  .GetIdentityServerIssuerUri();
        if (!client.Properties.TryGetValue(ApplicationProfilesPropertyNames.Profile, out var type)) {
            throw new InvalidOperationException($"Can't determine the type for the client '{clientId}'");
        }

        string responseType;
        switch (type) {
            case ApplicationProfiles.IdentityServerSpa:
            case ApplicationProfiles.Spa:
            case ApplicationProfiles.NativeApp:
                responseType = "code";
                break;
            default:
                throw new InvalidOperationException($"Invalid application type '{type}' for '{clientId}'.");
        }

        return new Dictionary<string, string> {
            ["authority"] = authority,
            ["client_id"] = client.ClientId,
            ["redirect_uri"] = UrlFactory.GetAbsoluteUrl(context, client.RedirectUris.First()),
            ["post_logout_redirect_uri"] = UrlFactory.GetAbsoluteUrl(context, client.PostLogoutRedirectUris.First()),
            ["response_type"] = responseType,
            ["scope"] = string.Join(" ", client.AllowedScopes),
        };
    }
}
