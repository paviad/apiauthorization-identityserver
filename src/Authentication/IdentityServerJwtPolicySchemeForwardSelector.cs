// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace ApiAuthorization.IdentityServer.Authentication;

internal sealed class IdentityServerJwtPolicySchemeForwardSelector(
    string identityPath,
    string identityServerJwtScheme) {
    private readonly PathString _identityPath = identityPath;

    public string SelectScheme(HttpContext ctx) {
        return ctx.Request.Path.StartsWithSegments(_identityPath, StringComparison.OrdinalIgnoreCase)
            ? IdentityConstants.ApplicationScheme
            : identityServerJwtScheme;
    }
}
