// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace ApiAuthorization.IdentityServer.Configuration;

internal sealed class ClientDefinition : ServiceDefinition {
    public string RedirectUri { get; set; }
    public string LogoutUri { get; set; }
    public string ClientSecret { get; set; }
}
