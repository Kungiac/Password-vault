import { Amplify } from "aws-amplify";

const region = process.env.NEXT_PUBLIC_AWS_REGION?.trim() ?? "";
const userPoolId = process.env.NEXT_PUBLIC_USER_POOL_ID?.trim() ?? "";
const userPoolWebClientId =
  process.env.NEXT_PUBLIC_USER_POOL_CLIENT_ID?.trim() ?? "";
const apiEndpoint = process.env.NEXT_PUBLIC_API_URL?.trim() ?? "";

/** True when Cognito env vars are set (Amplify Auth will work). */
export const isAmplifyAuthReady: boolean = Boolean(
  region && userPoolId && userPoolWebClientId
);

/** Env keys that must be set in `.env.local` (from CDK stack outputs). */
export function missingAmplifyAuthEnvKeys(): string[] {
  const missing: string[] = [];
  if (!region) missing.push("NEXT_PUBLIC_AWS_REGION");
  if (!userPoolId) missing.push("NEXT_PUBLIC_USER_POOL_ID");
  if (!userPoolWebClientId) missing.push("NEXT_PUBLIC_USER_POOL_CLIENT_ID");
  return missing;
}

if (isAmplifyAuthReady) {
  Amplify.configure({
    Auth: {
      region,
      userPoolId,
      userPoolWebClientId,
    },
    ...(apiEndpoint
      ? {
          API: {
            endpoints: [
              {
                name: "PasswordVaultAPI",
                endpoint: apiEndpoint.replace(/\/$/, ""),
                region,
              },
            ],
          },
        }
      : {}),
  });
} else if (typeof window !== "undefined") {
  console.warn(
    "[Password Vault] Amplify Auth is not configured: set NEXT_PUBLIC_AWS_REGION, " +
      "NEXT_PUBLIC_USER_POOL_ID, and NEXT_PUBLIC_USER_POOL_CLIENT_ID in frontend/.env.local " +
      "(from `cdk deploy` outputs), then restart `next dev`."
  );
}
