// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using ApiAuthorization.IdentityServer.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace ApiAuthorization.IdentityServer.TagHelpers;

/// <summary>
///     A tag helper for generating client parameters for a given oauth/openid client as data attributes.
/// </summary>
/// <remarks>
///     Initializes a new instance of <see cref="ClientParametersTagHelper" />.
/// </remarks>
/// <param name="clientRequestParametersProvider">The <see cref="IClientRequestParametersProvider" />.</param>
[HtmlTargetElement("*", Attributes = "[asp-apiauth-parameters]")]
[PublicAPI]
public class ClientParametersTagHelper(IClientRequestParametersProvider clientRequestParametersProvider) : TagHelper {
    /// <summary>
    ///     Gets or sets the client id.
    /// </summary>
    [HtmlAttributeName("asp-apiauth-parameters")]
    public string? ClientId { get; set; }

    /// <summary>
    ///     Gets or sets the ViewContext.
    /// </summary>
    [ViewContext]
    public ViewContext ViewContext { get; set; } = null!;

    /// <inheritdoc />
    public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output) {
        var parameters = await clientRequestParametersProvider.GetClientParametersAsync(ViewContext.HttpContext, ClientId) ??
                         throw new InvalidOperationException($"Parameters for client '{ClientId}' not found.");
        foreach (var parameter in parameters) {
            output.Attributes.Add("data-" + parameter.Key, parameter.Value);
        }
    }
}
