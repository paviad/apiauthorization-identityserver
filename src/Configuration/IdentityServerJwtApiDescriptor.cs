// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;

namespace ApiAuthorization.IdentityServer.Configuration;

internal sealed class IdentityServerJwtDescriptor(IWebHostEnvironment environment) : IIdentityServerJwtDescriptor {
    public IWebHostEnvironment Environment { get; } = environment;

    public IDictionary<string, ResourceDefinition> GetResourceDefinitions() {
        return new Dictionary<string, ResourceDefinition> {
            [Environment.ApplicationName + "API"] =
                new() { Profile = ApplicationProfiles.IdentityServerJwt },
        };
    }
}
