// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace ApiAuthorization.IdentityServer.Configuration;

internal sealed class KeyDefinition {
    public string? Type { get; init; }
    public bool? Persisted { get; set; }
    public string? FilePath { get; init; }
    public string? Password { get; init; }
    public string? Name { get; init; }
    public string? StoreLocation { get; init; }
    public string? StoreName { get; init; }
    public string? StorageFlags { get; init; }
}
