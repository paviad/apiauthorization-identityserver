// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Specialized;
using System.Net;
using ApiAuthorization.IdentityServer.Configuration;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Endpoints.Results;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Hosting;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ApiAuthorization.IdentityServer.Extensions;

internal sealed class AutoRedirectEndSessionEndpoint(
    ILogger<AutoRedirectEndSessionEndpoint> logger,
    IEndSessionRequestValidator requestValidator,
    IOptions<IdentityServerOptions> identityServerOptions,
    IUserSession session)
    : IEndpointHandler {
    private readonly ILogger _logger = logger;

    public async Task<IEndpointResult?> ProcessAsync(HttpContext ctx) {
        var validtionResult = ValidateRequest(ctx.Request);
        if (validtionResult != null) {
            return validtionResult;
        }

        var parameters = await GetParametersAsync(ctx.Request);
        var user = await session.GetUserAsync();
        var result = await requestValidator.ValidateAsync(parameters,
            user ?? throw new InvalidOperationException("User not found"));
        if (result.IsError) {
            _logger.LogError(LoggerEventIds.EndingSessionFailed, "Error ending session {Error}", result.Error);
            return new RedirectResult(identityServerOptions.Value.UserInteraction.ErrorUrl);
        }

        var dflt = identityServerOptions.Value.UserInteraction.LogoutUrl;
        var redirectUrl = await GetRedirectUrl() ?? dflt ?? "/";

        return new RedirectResult(redirectUrl);

        async Task<string?> GetRedirectUrl() {
            if (result.ValidatedRequest is not { Client: { } client }) {
                return null;
            }

            if (!client.Properties.TryGetValue(ApplicationProfilesPropertyNames.Profile, out _)) {
                return null;
            }

            var signInScheme = identityServerOptions.Value.Authentication.CookieAuthenticationScheme;
            if (signInScheme != null) {
                await ctx.SignOutAsync(signInScheme);
            }
            else {
                await ctx.SignOutAsync();
            }

            var postLogOutUri = result.ValidatedRequest.PostLogOutUri;
            if (result.ValidatedRequest.State != null) {
                postLogOutUri = QueryHelpers.AddQueryString(postLogOutUri, OpenIdConnectParameterNames.State,
                    result.ValidatedRequest.State);
            }

            return postLogOutUri;
        }
    }

    private static async Task<NameValueCollection> GetParametersAsync(HttpRequest request) {
        if (HttpMethods.IsGet(request.Method)) {
            return request.Query.AsNameValueCollection();
        }

        var form = await request.ReadFormAsync();
        return form.AsNameValueCollection();
    }

    private static StatusCodeResult? ValidateRequest(HttpRequest request) {
        if (!HttpMethods.IsPost(request.Method) && !HttpMethods.IsGet(request.Method)) {
            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }

        if (HttpMethods.IsPost(request.Method) &&
            !string.Equals(request.ContentType, "application/x-www-form-urlencoded",
                StringComparison.OrdinalIgnoreCase)) {
            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }

        return null;
    }

    internal sealed class RedirectResult(string url) : IEndpointResult {
        public string Url { get; } = url;

        public Task ExecuteAsync(HttpContext context) {
            context.Response.Redirect(Url);
            return Task.CompletedTask;
        }
    }
}
