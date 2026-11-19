# Auth

Infisical issues short-lived **access tokens** to machine identities. The client gets one on the
first authenticated call, refreshes it at 80 % of its lifetime, logs in again near the identity's
max TTL or when a renewal fails, and retries a request **once** after a fresh login when the server
answers 401. A rejected login is never retried (Infisical can lock an identity after repeated bad
secrets). Login, renew and revoke never send an `Authorization` header (the server rejects it).

| Method | Endpoint (v1) | In the Docker suite |
| - | - | - |
| `UniversalAuth(clientId, clientSecret)` — `login`, `renew`, `revoke` | `POST /api/v1/auth/universal-auth/login`, `POST /api/v1/auth/token/renew`, `POST /api/v1/auth/token/revoke` | full round trip |
| `TokenAuth(token)` — static token, never refreshed | — | identity token, user JWT and legacy `st.` service token |
| `KubernetesAuth(identityId, jwt \| tokenPath)` | `POST /api/v1/auth/kubernetes-auth/login` | request shape only (no TokenReview API in the fixture) |
| `AwsIamAuth(identityId, region, credentials)` — signs `sts:GetCallerIdentity` with SigV4 | `POST /api/v1/auth/aws-auth/login` | request shape only (no real STS) |

Static tokens are classified by kind for `ping()`: `st.…` is a legacy **service token**
(`serviceToken`), a JWT with `authTokenType: accessToken` is a **user** token (`user`), anything
else is a machine **identity** token (`identity`). TypeScript and Python expose the kind
(`TokenKind`, `TokenAuth(token, {kind})`) to override the detection.

The SDK configures Universal Auth from `clientId`/`clientSecret` (or the environment) on its own;
pass an explicit method only for the other kinds or to call `login`/`renew`/`revoke` yourself.
`revokeOnClose` revokes a token the client obtained by logging in when it is closed.

## Universal Auth: login → renew → revoke

In TypeScript and Python the calls are made on the method bound to a client; Go, Rust and Java use
the client's token manager (`client.Auth()`).

=== "TypeScript"

    ```ts
    import { InfisicalClient, UniversalAuth } from "@grow-codes/infisical";

    const ua = new UniversalAuth(process.env.INFISICAL_CLIENT_ID!, process.env.INFISICAL_CLIENT_SECRET!);
    const client = new InfisicalClient({ url: "http://infisical:8080", auth: ua });
    const token = await ua.login();       // AccessToken { expiresInMs, tokenType, … }
    await ua.renew();
    await ua.revoke();                    // the next call logs in again
    ```

=== "Rust"

    ```rust
    use grow_infisical::{InfisicalClient, InfisicalConfig, UniversalAuth};

    let config = InfisicalConfig::builder()
        .url("http://infisical:8080")
        .auth(UniversalAuth::new(client_id, client_secret))
        .build()?;
    let client = InfisicalClient::new(config)?;
    let token = client.auth().login().await?;
    client.auth().renew().await?;
    client.auth().revoke().await?;
    ```

=== "Go"

    ```go
    client, err := infisical.NewClient(infisical.Config{
        CommonConfig: infisical.CommonConfig{URL: "http://infisical:8080"},
        Auth:         infisical.NewUniversalAuth(clientID, clientSecret),
    })
    if err != nil {
        return err
    }
    tok, err := client.Auth().Login(ctx)
    _, err = client.Auth().Renew(ctx)
    err = client.Auth().Revoke(ctx)
    ```

=== "Python"

    ```python
    import grow_infisical as sdk

    ua = sdk.UniversalAuth(client_id, client_secret)
    with sdk.InfisicalClient(sdk.InfisicalConfig(url="http://infisical:8080", auth=ua)) as client:
        token = ua.login()        # AccessToken(expires_in_s=…, token_type="Bearer")
        ua.renew()
        ua.revoke()               # the next call logs in again
    ```

=== "Java"

    ```java
    try (InfisicalClient client = InfisicalClient.builder()
            .url("http://infisical:8080")
            .auth(new UniversalAuth(clientId, clientSecret))
            .build()) {
        AccessToken token = client.auth().login();
        client.auth().renew();
        client.auth().revoke();
    }
    ```

## Static tokens, Kubernetes and AWS IAM

=== "TypeScript"

    ```ts
    import { AwsIamAuth, InfisicalClient, KubernetesAuth, TokenAuth } from "@grow-codes/infisical";

    const viewer = new InfisicalClient({ auth: new TokenAuth(process.env.INFISICAL_TOKEN!) });
    const k8s = new KubernetesAuth({ identityId }); // reads the service-account token file
    const aws = new AwsIamAuth({ identityId, region: "eu-central-1" }); // AWS_* credentials
    const client = new InfisicalClient({ auth: k8s });
    ```

=== "Rust"

    ```rust
    use grow_infisical::{AwsIamAuth, KubernetesAuth, TokenAuth};

    let viewer = TokenAuth::new(token);
    let k8s = KubernetesAuth::new(identity_id); // .jwt(…) or .token_path(…)
    let aws = AwsIamAuth::new(identity_id).region("eu-central-1"); // AWS_* credentials
    let config = InfisicalConfig::builder().auth(k8s).build()?;
    ```

=== "Go"

    ```go
    viewer := infisical.NewTokenAuth(token)
    k8s := &infisical.KubernetesAuth{IdentityID: identityID} // JWT or TokenPath
    aws := &infisical.AwsIamAuth{IdentityID: identityID, Region: "eu-central-1"} // AWS_* credentials
    client, err := infisical.NewClient(infisical.Config{Auth: k8s})
    ```

=== "Python"

    ```python
    viewer = sdk.TokenAuth(token)
    k8s = sdk.KubernetesAuth(identity_id)          # jwt=… or the service-account token file
    aws = sdk.AwsIamAuth(identity_id, region="eu-central-1")  # AWS_* credentials
    client = sdk.InfisicalClient(sdk.InfisicalConfig(auth=k8s))
    ```

=== "Java"

    ```java
    TokenAuth viewer = new TokenAuth(token);
    KubernetesAuth k8s = KubernetesAuth.builder().identityId(identityId).build();
    AwsIamAuth aws = AwsIamAuth.builder().identityId(identityId).region("eu-central-1").build();
    InfisicalClient client = InfisicalClient.builder().auth(k8s).build();
    ```

Kubernetes and AWS IAM logins cannot succeed against the Docker fixture; their request shape is
checked against the real server (it answers "auth method not found" → `NOT_FOUND`) and their
success path is unit-tested, including the SigV4 signature against the AWS test vectors.
