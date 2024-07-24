// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using ApiAuthorization.IdentityServer.Configuration;
using Duende.IdentityServer.Services;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace ApiAuthorization.IdentityServer.Authentication;

/// <summary>
///     Extension methods to configure authentication for existing APIs coexisting with an Authorization Server.
/// </summary>
[PublicAPI]
public static class AuthenticationBuilderExtensions {
    private const string IdentityServerJwtNameSuffix = "API";

    private static readonly PathString DefaultIdentityUiPathPrefix = new("/Identity");

    /// <summary>
    ///     Adds an authentication handler for an API that coexists with an Authorization Server.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder" />.</param>
    /// <returns>The <see cref="AuthenticationBuilder" />.</returns>
    public static AuthenticationBuilder AddIdentityServerJwt(this AuthenticationBuilder builder) {
        var services = builder.Services;
        services.TryAddSingleton<IIdentityServerJwtDescriptor, IdentityServerJwtDescriptor>();
        services.TryAddEnumerable(ServiceDescriptor
            .Transient<IConfigureOptions<JwtBearerOptions>, IdentityServerJwtBearerOptionsConfiguration>(
                JwtBearerOptionsFactory));

        services.AddAuthentication(IdentityServerJwtConstants.IdentityServerJwtScheme)
            .AddPolicyScheme(IdentityServerJwtConstants.IdentityServerJwtScheme, null, options => {
                options.ForwardDefaultSelector = new IdentityServerJwtPolicySchemeForwardSelector(
                    DefaultIdentityUiPathPrefix,
                    IdentityServerJwtConstants.IdentityServerJwtBearerScheme).SelectScheme;
            })
            .AddJwtBearer(IdentityServerJwtConstants.IdentityServerJwtBearerScheme, null, _ => { });

        return builder;

        static IdentityServerJwtBearerOptionsConfiguration JwtBearerOptionsFactory(IServiceProvider sp) {
            var schemeName = IdentityServerJwtConstants.IdentityServerJwtBearerScheme;

            var localApiDescriptor = sp.GetRequiredService<IIdentityServerJwtDescriptor>();
            var hostingEnvironment = sp.GetRequiredService<IWebHostEnvironment>();
            var issuerNameService = sp.GetRequiredService<IIssuerNameService>();
            var apiName = hostingEnvironment.ApplicationName + IdentityServerJwtNameSuffix;

            return new IdentityServerJwtBearerOptionsConfiguration(schemeName, apiName, issuerNameService,
                localApiDescriptor);
        }
    }
}
