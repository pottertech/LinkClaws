/**
 * LinkedIn OAuth 2.0 / OpenID Connect utilities
 * 
 * Uses "Sign In with LinkedIn using OpenID Connect" API
 * Docs: https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
 */

// LinkedIn OAuth endpoints
export const LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization";
export const LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken";
export const LINKEDIN_USERINFO_URL = "https://api.linkedin.com/v2/userinfo";

// Required scopes for OpenID Connect
export const LINKEDIN_SCOPES = ["openid", "profile", "email"];

// State token expiration (15 minutes)
export const STATE_EXPIRATION_MS = 15 * 60 * 1000;

/**
 * Generate a cryptographically secure state token for OAuth CSRF protection
 */
export function generateOAuthState(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const randomValues = new Uint8Array(32);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(randomValues[i] % chars.length);
  }
  return result;
}

/**
 * Build the LinkedIn authorization URL
 */
export function buildLinkedInAuthUrl(
  clientId: string,
  redirectUri: string,
  state: string
): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state: state,
    scope: LINKEDIN_SCOPES.join(" "),
  });
  return `${LINKEDIN_AUTH_URL}?${params.toString()}`;
}

/**
 * LinkedIn token response shape
 */
export interface LinkedInTokenResponse {
  access_token: string;
  expires_in: number;
  scope?: string;
  token_type?: string;
}

/**
 * LinkedIn userinfo response shape (OpenID Connect)
 */
export interface LinkedInProfile {
  sub: string;           // LinkedIn member ID (unique identifier)
  name: string;          // Full name
  given_name: string;    // First name
  family_name: string;   // Last name
  email: string;         // Email address
  email_verified: boolean;
  picture?: string;      // Profile picture URL
  locale?: {
    country: string;
    language: string;
  };
}

/**
 * Exchange authorization code for access token
 */
export async function exchangeCodeForToken(
  code: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string
): Promise<LinkedInTokenResponse> {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret,
  });

  const response = await fetch(LINKEDIN_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`LinkedIn token exchange failed: ${response.status} - ${errorText}`);
  }

  return response.json() as Promise<LinkedInTokenResponse>;
}

/**
 * Fetch user profile from LinkedIn using access token
 */
export async function fetchLinkedInProfile(
  accessToken: string
): Promise<LinkedInProfile> {
  const response = await fetch(LINKEDIN_USERINFO_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`LinkedIn profile fetch failed: ${response.status} - ${errorText}`);
  }

  return response.json() as Promise<LinkedInProfile>;
}

/**
 * Complete LinkedIn OAuth flow: exchange code and fetch profile
 */
export async function completeLinkedInOAuth(
  code: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string
): Promise<LinkedInProfile> {
  const tokenResponse = await exchangeCodeForToken(
    code,
    clientId,
    clientSecret,
    redirectUri
  );
  
  return fetchLinkedInProfile(tokenResponse.access_token);
}

