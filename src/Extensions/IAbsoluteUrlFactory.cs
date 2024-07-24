﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Http;

namespace ApiAuthorization.IdentityServer.Extensions;

internal interface IAbsoluteUrlFactory {
    string GetAbsoluteUrl(string path);
    string GetAbsoluteUrl(HttpContext context, string path);
}
