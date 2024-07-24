// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using ApiAuthorization.IdentityServer.Options;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ApiAuthorization.IdentityServer.Configuration;

internal sealed class ConfigureApiResources(
    IConfiguration configuration,
    IIdentityServerJwtDescriptor localApiDescriptor,
    ILogger<ConfigureApiResources> logger)
    : IConfigureOptions<ApiAuthorizationOptions> {
    private const char ScopesSeparator = ' ';

    public void Configure(ApiAuthorizationOptions options) {
        var resources = GetApiResources();
        foreach (var resource in resources) {
            options.ApiResources.Add(resource);
        }
    }

    public static ApiResource GetResource(string name, ResourceDefinition definition) {
        switch (definition.Profile) {
            case ApplicationProfiles.Api:
                return GetApi(name, definition);
            case ApplicationProfiles.IdentityServerJwt:
                return GetLocalApi(name, definition);
            default:
                throw new InvalidOperationException($"Type '{definition.Profile}' is not supported.");
        }
    }

    internal IEnumerable<ApiResource> GetApiResources() {
        var data = configuration
            .Get<Dictionary<string, ResourceDefinition>>();

        if (data != null) {
            foreach (var kvp in data) {
                logger.LogInformation(LoggerEventIds.ConfiguringApiResource,
                    "Configuring API resource '{ApiResourceName}'.", kvp.Key);
                yield return GetResource(kvp.Key, kvp.Value);
            }
        }

        var localResources = localApiDescriptor?.GetResourceDefinitions();
        if (localResources != null) {
            foreach (var kvp in localResources) {
                logger.LogInformation(LoggerEventIds.ConfiguringLocalApiResource,
                    "Configuring local API resource '{ApiResourceName}'.", kvp.Key);
                yield return GetResource(kvp.Key, kvp.Value);
            }
        }
    }

    private static ApiResource GetApi(string name, ResourceDefinition definition) =>
        ApiResourceBuilder.ApiResource(name)
            .FromConfiguration()
            .WithAllowedClients(ApplicationProfilesPropertyValues.AllowAllApplications)
            .ReplaceScopes(ParseScopes(definition.Scopes) ?? [name])
            .Build();

    private static ApiResource GetLocalApi(string name, ResourceDefinition definition) =>
        ApiResourceBuilder.IdentityServerJwt(name)
            .FromConfiguration()
            .WithAllowedClients(ApplicationProfilesPropertyValues.AllowAllApplications)
            .ReplaceScopes(ParseScopes(definition.Scopes) ?? [name])
            .Build();

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
