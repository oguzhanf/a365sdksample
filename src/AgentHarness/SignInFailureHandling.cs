// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using Microsoft.AspNetCore.Authentication;

namespace AgentHarness;

public static class SignInFailureHandling
{
    public const string ExpiredPath = "/auth/sign-in-expired";

    public static Task OnRemoteFailureAsync(RemoteFailureContext context)
    {
        for (var failure = context.Failure; failure is not null; failure = failure.InnerException)
        {
            if (failure is not AuthenticationFailureException ||
                !string.Equals(failure.Message, "Correlation failed.", StringComparison.Ordinal))
                continue;

            context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger("AgentHarness.SignIn")
                .LogWarning("Sign-in rejected because its correlation cookie was missing or expired. TraceId: {TraceId}",
                    Activity.Current?.TraceId.ToString() ?? context.HttpContext.TraceIdentifier);
            context.HandleResponse();
            context.Response.Headers.CacheControl = "no-store";
            context.Response.StatusCode = StatusCodes.Status303SeeOther;
            context.Response.Headers.Location = ExpiredPath;
            break;
        }
        return Task.CompletedTask;
    }

    public static IResult ExpiredPage(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        return Results.Content("""
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Sign-in session expired | AgentHarness</title>
                <link rel="stylesheet" href="/styles.css">
                <link rel="icon" href="/favicon.svg" type="image/svg+xml">
            </head>
            <body>
                <main class="signed-out">
                    <section class="landing-card" aria-labelledby="expired-title">
                        <p class="eyebrow">AgentHarness</p>
                        <h1 id="expired-title">Sign-in session expired</h1>
                        <p class="landing-lead">The sign-in cookie expired or was not returned by your browser.
                            No session was created. Start again from this application instead of refreshing the old callback.</p>
                        <div class="landing-actions">
                            <a class="button button-primary" href="/auth/login">Start sign-in again</a>
                            <a class="button button-secondary" href="/">Return to the harness</a>
                        </div>
                        <p class="landing-footnote">Keep cookies enabled for this site and complete the new sign-in promptly.
                            Your existing Microsoft Entra browser session can be reused when available.</p>
                    </section>
                </main>
            </body>
            </html>
            """, "text/html; charset=utf-8", statusCode: StatusCodes.Status401Unauthorized);
    }
}
