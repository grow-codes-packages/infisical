package codes.grow.packages.infisical;

/**
 * The login body {@link AwsIamAuth} sends (exposed for tests and debugging).
 *
 * @param identityId machine identity id
 * @param iamHttpRequestMethod method of the signed STS call ({@code POST})
 * @param iamRequestBody base64 of {@code Action=GetCallerIdentity&Version=2011-06-15}
 * @param iamRequestHeaders base64 of the JSON object of the signed headers
 * @param organizationSlug sub-organization slug ({@code ""} when none)
 */
public record AwsLoginRequest(
    String identityId,
    String iamHttpRequestMethod,
    String iamRequestBody,
    String iamRequestHeaders,
    String organizationSlug) {}
