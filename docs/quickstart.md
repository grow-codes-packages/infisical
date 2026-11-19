# Quickstart

Connect to Infisical with a machine identity, check that it is healthy, read a secret and close
the client. The client reads its settings from the environment (see
[Functions → Service configuration](functions.md#service-configuration)) or takes them in code.

```sh
export GROW_INFISICAL_URL=http://127.0.0.1:8080      # or INFISICAL_API_URL=https://…/api
export INFISICAL_CLIENT_ID=...                       # Universal Auth machine identity
export INFISICAL_CLIENT_SECRET=...                   # never commit real credentials
export INFISICAL_PROJECT_ID=...
export INFISICAL_ENVIRONMENT=dev
```

With `INFISICAL_TOKEN` (an access token, a user JWT or a legacy `st.` service token) instead of the
client id and secret, the token is used as it is and never refreshed.

=== "TypeScript"

    ```ts
    import { InfisicalClient } from "@grow-codes/infisical";

    const client = InfisicalClient.fromEnv();
    try {
      const health = await client.health();          // never throws for an unreachable server
      console.log("healthy:", health.healthy, health.status);
      console.log("ping:", await client.ping(), "ms"); // logs in with Universal Auth
      const url = await client.provider.getString("DATABASE_URL"); // null when missing
      const secret = await client.secrets.getSecret("DATABASE_URL"); // raw API: version, tags, …
      console.log(secret.key, secret.version, url !== null);
    } finally {
      await client.close();
    }
    ```

=== "Rust"

    ```rust
    use grow_infisical::secrets::SecretsProvider;
    use grow_infisical::InfisicalClient;

    #[tokio::main]
    async fn main() -> grow_infisical::Result<()> {
        let client = InfisicalClient::from_env()?;
        let health = client.health().await?;
        println!("healthy: {} {}", health.healthy, health.status);
        println!("ping: {:?}", client.ping().await?);
        let url = client.secrets().get_string("DATABASE_URL", None).await?; // None when missing
        let secret = client.get_secret("DATABASE_URL", None).await?;
        println!("{} v{} {}", secret.key, secret.version, url.is_some());
        client.close().await;
        Ok(())
    }
    ```

=== "Go"

    ```go
    package main

    import (
        "context"
        "fmt"
        "log"

        infisical "github.com/grow-codes-packages/infisical/go"
    )

    func main() {
        ctx := context.Background()
        client, err := infisical.NewClientFromEnv()
        if err != nil {
            log.Fatal(err) // CONFIG error naming the variable, never its value
        }
        defer client.Close()

        health, err := client.Health(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("healthy:", health.Healthy, health.Status)
        url, ok, err := client.Secrets().GetString(ctx, "DATABASE_URL", nil)
        if err != nil {
            log.Fatal(err)
        }
        secret, err := client.GetSecret(ctx, "DATABASE_URL", nil)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println(secret.Key, secret.Version, ok, len(url) > 0)
    }
    ```

=== "Python"

    ```python
    from grow_infisical import InfisicalClient

    with InfisicalClient.from_env() as client:
        health = client.health()
        print("healthy:", health.healthy, health.status)
        print("ping:", client.ping(), "ms")
        url = client.provider.get_string("DATABASE_URL")  # None when missing
        secret = client.secrets.get_secret("DATABASE_URL")
        print(secret.key, secret.version, url is not None)
    ```

    Async code uses `AsyncInfisicalClient` with the same methods (`async with`, `await`).

=== "Java"

    ```java
    import codes.grow.packages.infisical.InfisicalClient;
    import codes.grow.packages.infisical.SecretEntry;
    import java.util.Optional;

    try (InfisicalClient client = InfisicalClient.fromEnv()) {
        var health = client.health();
        System.out.println("healthy: " + health.healthy() + " " + health.status());
        System.out.println("ping: " + client.ping());
        Optional<String> url = client.secrets().getString("DATABASE_URL");
        SecretEntry secret = client.getSecret("DATABASE_URL");
        System.out.println(secret.key() + " v" + secret.version() + " " + url.isPresent());
    }
    ```

Next: the [Functions](functions.md) pages show every call with an example per language, and
[Error handling](errors.md) lists the error codes. `serverVersion()` always raises `UNSUPPORTED`:
Infisical does not report its version over the API.
