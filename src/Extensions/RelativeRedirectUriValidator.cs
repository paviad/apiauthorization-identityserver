// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using ApiAuthorization.IdentityServer.Configuration;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;

namespace ApiAuthorization.IdentityServer.Extensions;

internal sealed class RelativeRedirectUriValidator(IAbsoluteUrlFactory absoluteUrlFactory)
    : StrictRedirectUriValidator {
    public IAbsoluteUrlFactory AbsoluteUrlFactory { get; } =
        absoluteUrlFactory ?? throw new ArgumentNullException(nameof(absoluteUrlFactory));

    public override Task<bool> IsPostLogoutRedirectUriValidAsync(string requestedUri, Client client) {
        if (IsLocalSpa(client)) {
            return ValidateRelativeUris(requestedUri, client.PostLogoutRedirectUris);
        }

        return base.IsPostLogoutRedirectUriValidAsync(requestedUri, client);
    }

    public override Task<bool> IsRedirectUriValidAsync(string requestedUri, Client client) {
        if (IsLocalSpa(client)) {
            return ValidateRelativeUris(requestedUri, client.RedirectUris);
        }

        return base.IsRedirectUriValidAsync(requestedUri, client);
    }

    private static bool IsLocalSpa(Client client) =>
        client.Properties.TryGetValue(ApplicationProfilesPropertyNames.Profile, out var clientType) &&
        ApplicationProfiles.IdentityServerSpa == clientType;

    private Task<bool> ValidateRelativeUris(string requestedUri, IEnumerable<string> clientUris) {
        foreach (var url in clientUris) {
            if (Uri.IsWellFormedUriString(url, UriKind.Relative)) {
                var newUri = AbsoluteUrlFactory.GetAbsoluteUrl(url);
                if (string.Equals(newUri, requestedUri, StringComparison.Ordinal)) {
                    return Task.FromResult(true);
                }
            }
        }

        return Task.FromResult(false);
    }
}
