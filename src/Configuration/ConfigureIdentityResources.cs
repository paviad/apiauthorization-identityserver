// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using ApiAuthorization.IdentityServer.Options;
using Duende.IdentityServer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace ApiAuthorization.IdentityServer.Configuration;

internal sealed class ConfigureIdentityResources(IConfiguration configuration)
    : IConfigureOptions<ApiAuthorizationOptions> {
    private const char ScopesSeparator = ' ';

    public void Configure(ApiAuthorizationOptions options) {
        var data = configuration.Get<IdentityResourceDefinition>();
        if (data is { Scopes: not null }) {
            var scopes = ParseScopes(data.Scopes);
            if (scopes is { Length: > 0 }) {
                ClearDefaultIdentityResources(options);
            }

            foreach (var scope in scopes) {
                switch (scope) {
                    case IdentityServerConstants.StandardScopes.OpenId:
                        options.IdentityResources.Add(IdentityResourceBuilder.OpenId()
                            .AllowAllClients()
                            .FromConfiguration()
                            .Build());
                        break;
                    case IdentityServerConstants.StandardScopes.Profile:
                        options.IdentityResources.Add(IdentityResourceBuilder.Profile()
                            .AllowAllClients()
                            .FromConfiguration()
                            .Build());
                        break;
                    case IdentityServerConstants.StandardScopes.Address:
                        options.IdentityResources.Add(IdentityResourceBuilder.Address()
                            .AllowAllClients()
                            .FromConfiguration()
                            .Build());
                        break;
                    case IdentityServerConstants.StandardScopes.Email:
                        options.IdentityResources.Add(IdentityResourceBuilder.Email()
                            .AllowAllClients()
                            .FromConfiguration()
                            .Build());
                        break;
                    case IdentityServerConstants.StandardScopes.Phone:
                        options.IdentityResources.Add(IdentityResourceBuilder.Phone()
                            .AllowAllClients()
                            .FromConfiguration()
                            .Build());
                        break;
                    default:
                        throw new InvalidOperationException($"Invalid identity resource name '{scope}'");
                }
            }
        }
    }

    private static void ClearDefaultIdentityResources(ApiAuthorizationOptions options) {
        var allDefault = true;
        foreach (var resource in options.IdentityResources) {
            if (!resource.Properties.TryGetValue(ApplicationProfilesPropertyNames.Source, out var source) ||
                !string.Equals(ApplicationProfilesPropertyValues.Default, source, StringComparison.OrdinalIgnoreCase)) {
                allDefault = false;
                break;
            }
        }

        if (allDefault) {
            options.IdentityResources.Clear();
        }
    }

    private static string[] ParseScopes(string scopes) {
        if (scopes == null) {
            return null;
        }

        var parsed = scopes.Split(ScopesSeparator, StringSplitOptions.RemoveEmptyEntries);
        if (parsed.Length == 0) {
            return null;
        }

        return parsed;
    }
}
