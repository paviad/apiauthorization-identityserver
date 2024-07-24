// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading.Tasks;
using ApiAuthorization.IdentityServer.Configuration;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ApiAuthorization.IdentityServer.Authentication;

internal sealed class IdentityServerJwtBearerOptionsConfiguration(
    string scheme,
    string apiName,
    IIssuerNameService issuerNameService,
    IIdentityServerJwtDescriptor localApiDescriptor)
    : IConfigureNamedOptions<JwtBearerOptions> {
    public void Configure(string name, JwtBearerOptions options) {
        var definitions = localApiDescriptor.GetResourceDefinitions();
        if (!definitions.ContainsKey(apiName)) {
            return;
        }

        if (string.Equals(name, scheme, StringComparison.Ordinal)) {
            options.Events ??= new JwtBearerEvents();
            options.Events.OnMessageReceived = ResolveAuthorityAndKeysAsync;
            options.Audience = apiName;

            var staticConfiguration = new OpenIdConnectConfiguration {
                Issuer = options.Authority,
            };

            var manager = new StaticConfigurationManager(staticConfiguration);
            options.ConfigurationManager = manager;
            options.TokenValidationParameters.ValidIssuer = options.Authority;
            options.TokenValidationParameters.NameClaimType = "name";
            options.TokenValidationParameters.RoleClaimType = "role";
        }
    }

    public void Configure(JwtBearerOptions options) { }

    internal async Task ResolveAuthorityAndKeysAsync(MessageReceivedContext messageReceivedContext) {
        var options = messageReceivedContext.Options;
        if (options.TokenValidationParameters.ValidIssuer == null ||
            options.TokenValidationParameters.IssuerSigningKey == null) {
            var store = messageReceivedContext.HttpContext.RequestServices
                .GetRequiredService<ISigningCredentialStore>();
            var credential = await store.GetSigningCredentialsAsync();
            var authority = await issuerNameService.GetCurrentAsync();
            options.Authority ??= authority;
            options.TokenValidationParameters.IssuerSigningKey = credential.Key;
            options.TokenValidationParameters.ValidIssuer = options.Authority;
        }
    }
}
