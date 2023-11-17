import {redirect, type SessionStorage } from '@remix-run/server-runtime';
import {
  OAuth2Profile,
  OAuth2Strategy,
  OAuth2StrategyVerifyParams,
} from "remix-auth-oauth2";
import type { StrategyVerifyCallback } from "remix-auth";

export interface Session {
    accessToken: string;
    expiresAt: number;
    refreshToken?: string;
    tokenType?: string;
    user: any;
}
export interface Auth0StrategyOptions {
  domain: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: Auth0Scope[] | string;
  audience?: string;
  organization?: string;
  connection?: string;
}

/**
 * @see https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes#standard-claims
 */
export type Auth0Scope = "openid" | "profile" | "email" | string;

export interface Auth0Profile extends OAuth2Profile {
  _json?: Auth0UserInfo;
  organizationId?: string;
  organizationName?: string;
}

export interface Auth0ExtraParams extends Record<string, unknown> {
  id_token?: string;
  scope: string;
  expires_in: number;
  token_type: "Bearer";
}

interface Auth0UserInfo {
  sub?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    country?: string;
  };
  updated_at?: string;
  org_id?: string;
  org_name?: string;
}

export const Auth0StrategyDefaultName = "auth0";
export const Auth0StrategyDefaultScope: Auth0Scope = "openid profile email";
export const Auth0StrategyScopeSeperator = " ";

export class Auth0Strategy<User> extends OAuth2Strategy<
  User,
  Auth0Profile,
  Auth0ExtraParams
> {
  name = Auth0StrategyDefaultName;

  private userInfoURL: string;
  private scope: Auth0Scope[];
  private audience?: string;
  private organization?: string;
  private connection?: string;
  private fetchProfile: boolean;
  private readonly sessionStorage: SessionStorage;

  constructor(
    options: Auth0StrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<Auth0Profile, Auth0ExtraParams>
    >,
    sessionStorage: SessionStorage,
  ) {
    super(
      {
        authorizationURL: `https://${options.domain}/authorize`,
        tokenURL: `https://${options.domain}/oauth/token`,
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
      },
      verify,
    );

    this.userInfoURL = `https://${options.domain}/userinfo`;
    this.scope = this.getScope(options.scope);
    this.audience = options.audience;
    this.organization = options.organization;
    this.connection = options.connection;
    this.fetchProfile = this.scope
      .join(Auth0StrategyScopeSeperator)
      .includes("openid");
    this.sessionStorage = sessionStorage;
  }

  // Allow users the option to pass a scope string, or typed array
  private getScope(scope: Auth0StrategyOptions["scope"]) {
    if (!scope) {
      return [Auth0StrategyDefaultScope];
    } else if (typeof scope === "string") {
      return scope.split(Auth0StrategyScopeSeperator) as Auth0Scope[];
    }

    return scope;
  }

  protected authorizationParams(params: URLSearchParams) {
    params.set("scope", this.scope.join(Auth0StrategyScopeSeperator));
    if (this.audience) {
      params.set("audience", this.audience);
    }
    if (this.organization) {
      params.set("organization", this.organization);
    }
    if (this.connection) {
      params.set("connection", this.connection);
    }

    return params;
  }

  protected async userProfile(accessToken: string): Promise<Auth0Profile> {
    let profile: Auth0Profile = {
      provider: Auth0StrategyDefaultName,
    };

    if (!this.fetchProfile) {
      return profile;
    }

    let response = await fetch(this.userInfoURL, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    let data: Auth0UserInfo = await response.json();

    profile._json = data;

    if (data.sub) {
      profile.id = data.sub;
    }

    if (data.name) {
      profile.displayName = data.name;
    }

    if (data.family_name || data.given_name || data.middle_name) {
      profile.name = {};

      if (data.family_name) {
        profile.name.familyName = data.family_name;
      }

      if (data.given_name) {
        profile.name.givenName = data.given_name;
      }

      if (data.middle_name) {
        profile.name.middleName = data.middle_name;
      }
    }

    if (data.email) {
      profile.emails = [{ value: data.email }];
    }

    if (data.picture) {
      profile.photos = [{ value: data.picture }];
    }

    if (data.org_id) {
      profile.organizationId = data.org_id;
    }

    if (data.org_name) {
      profile.organizationName = data.org_name;
    }

    return profile;
  }

  protected parseJwt(token: string) {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  }

  async getSession(
        req: Request,
    ) {
    const options = {
      name: "auth0",
      sessionKey: "user",
      sessionErrorKey: "auth:error",
      sessionStrategyKey: "strategy",
      throwOnError: false,
    }
    const cookie = req.headers.get('Cookie');
    const session = await this.sessionStorage.getSession(
      req.headers.get('Cookie'),
    );
    const accessToken = session.get("user")?.accessToken;
    const refreshToken = session.get("user")?.accessToken;
    if (!accessToken || !refreshToken) {
      session.unset("oauth2:state");
      return null;
    }
    const decoded = this.parseJwt(accessToken);
    const expiration = new Date(decoded.exp * 1000);
    const expired = new Date() > expiration;

    if (expired) {
      try {
        const v = await this.refreshToken(refreshToken, req);
        return v;
      } catch(e) {
        console.log("REFRESH Token failed", e);
        const cookie = await this.sessionStorage.destroySession(session);
        throw redirect("/login", {headers: {"Set-Cookie": cookie}});
      }

    }
    const user = await this.verify({
      accessToken: session.get("user").accessToken,
      refreshToken: session.get("user").refreshToken,
      extraParams: {
        scope: "",
        expires_in: 0,
        token_type: "Bearer",
      },
      profile: session.get("user"),
      request: req,
    });
    return await this.success(user, req, this.sessionStorage, options);
  }

  async refreshToken(token: any, request: any) {
    const options = {
      name: "auth0",
      sessionKey: "user",
      sessionErrorKey: "auth:error",
      sessionStrategyKey: "strategy",
      throwOnError: false,
    }
    let user;
    try {
      // Get the access token
      let params = new URLSearchParams(this.tokenParams());
      params.set("grant_type", "refresh_token");
      //params.set("redirect_uri", callbackURL.toString());
      let { accessToken, refreshToken, extraParams } = await this.fetchAccessToken(token, params);
      // Get the profile
      let profile = await this.userProfile(accessToken);
      // Verify the user and return it, or redirect
      user = await this.verify({
          accessToken,
          refreshToken,
          extraParams,
          profile,
          request,
      });
    }
    catch (error) {
      console.log("Failed to verify user", error);
      // Allow responses to pass-through
      if (error instanceof Response)
        throw error;
      if (error instanceof Error) {
        return await this.failure(error.message, request, this.sessionStorage, options, error);
      }
      if (typeof error === "string") {
        return await this.failure(error, request, this.sessionStorage, options, new Error(error));
      }
      return await this.failure("Unknown error", request, this.sessionStorage, options, new Error(JSON.stringify(error, null, 2)));
    }
    return await this.success(user, request, this.sessionStorage, options);

  }
}
