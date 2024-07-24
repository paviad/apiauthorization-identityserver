﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace ApiAuthorization.IdentityServer.Configuration;

internal class ResourceDefinition : ServiceDefinition {
    public string Scopes { get; set; }
}