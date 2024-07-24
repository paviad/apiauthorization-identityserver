// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using ApiAuthorization.IdentityServer.Options;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ApiAuthorization.IdentityServer.Configuration;

internal sealed class ConfigureClients(
    IConfiguration configuration,
    ILogger<ConfigureClients> logger)
    : IConfigureOptions<ApiAuthorizationOptions> {
    private const string DefaultLocalSpaRelativeRedirectUri = "/authentication/login-callback";
    private const string DefaultLocalSpaRelativePostLogoutRedirectUri = "/authentication/logout-callback";

    public void Configure(ApiAuthorizationOptions options) {
        foreach (var client in GetClients()) {
            options.Clients.Add(client);
        }
    }

    internal IEnumerable<Client> GetClients() {
        var data = configuration.Get<Dictionary<string, ClientDefinition>>();
        if (data != null) {
            foreach (var kvp in data) {
                logger.LogInformation(LoggerEventIds.ConfiguringClient, "Configuring client '{ClientName}'.", kvp.Key);
                var name = kvp.Key;
                var definition = kvp.Value;

                switch (definition.Profile) {
                    case ApplicationProfiles.Spa:
                        yield return GetSpa(name, definition);
                        break;
                    case ApplicationProfiles.IdentityServerSpa:
                        yield return GetLocalSpa(name, definition);
                        break;
                    case ApplicationProfiles.NativeApp:
                        yield return GetNativeApp(name);
                        break;
                    default:
                        throw new InvalidOperationException($"Type '{definition.Profile}' is not supported.");
                }
            }
        }
    }

    private static Client GetLocalSpa(string name, ClientDefinition definition) {
        var client = ClientBuilder
            .IdentityServerSpa(name)
            .WithRedirectUri(definition.RedirectUri ?? DefaultLocalSpaRelativeRedirectUri)
            .WithLogoutRedirectUri(definition.LogoutUri ?? DefaultLocalSpaRelativePostLogoutRedirectUri)
            .WithAllowedOrigins()
            .FromConfiguration();

        return client.Build();
    }

    private static Client GetNativeApp(string name) {
        var client = ClientBuilder.NativeApp(name)
            .FromConfiguration();
        return client.Build();
    }

    private static Client GetSpa(string name, ClientDefinition definition) {
        if (definition.RedirectUri == null ||
            !Uri.TryCreate(definition.RedirectUri, UriKind.Absolute, out var redirectUri)) {
            throw new InvalidOperationException($"The redirect uri " +
                                                $"'{definition.RedirectUri}' for '{name}' is invalid. " +
                                                $"The redirect URI must be an absolute url.");
        }

        if (definition.LogoutUri == null ||
            !Uri.TryCreate(definition.LogoutUri, UriKind.Absolute, out var postLogouturi)) {
            throw new InvalidOperationException($"The logout uri " +
                                                $"'{definition.LogoutUri}' for '{name}' is invalid. " +
                                                $"The logout URI must be an absolute url.");
        }

        if (!string.Equals(
                redirectUri.GetLeftPart(UriPartial.Authority),
                postLogouturi.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal)) {
            throw new InvalidOperationException($"The redirect uri and the logout uri " +
                                                $"for '{name}' have a different scheme, host or port.");
        }

        var client = ClientBuilder.Spa(name)
            .WithRedirectUri(definition.RedirectUri)
            .WithLogoutRedirectUri(definition.LogoutUri)
            .WithAllowedOrigins(redirectUri.GetLeftPart(UriPartial.Authority))
            .FromConfiguration();

        return client.Build();
    }
}
