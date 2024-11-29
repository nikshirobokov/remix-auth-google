import { OAuth2Strategy } from 'remix-auth-oauth2'
import type { Strategy } from 'remix-auth/strategy'

/**
 * @see https://developers.google.com/identity/protocols/oauth2/scopes
 */
export type GoogleScope = string

export type GoogleStrategyOptions = {
  clientId: string
  clientSecret: string
  redirectURI: string
  /**
   * @default "openid profile email"
   */
  scopes?: GoogleScope[]
  accessType?: 'online' | 'offline'
  includeGrantedScopes?: boolean
  prompt?: 'none' | 'consent' | 'select_account'
  hd?: string
  loginHint?: string
}

interface OAuth2Profile {
  provider: string
  name?: {
    familyName?: string
    givenName?: string
    middleName?: string
  }
}

export type GoogleProfile = {
  id: string
  displayName: string
  name: {
    familyName: string
    givenName: string
  }
  emails: [{ value: string; type?: string }]
  photos: [{ value: string }]
  _json: {
    sub: string
    name: string
    given_name: string
    family_name: string
    picture: string
    locale: string
    email: string
    email_verified: boolean
    hd: string
  }
} & OAuth2Profile

export type GoogleExtraParams = {
  expires_in: 3920
  token_type: 'Bearer'
  scope: string
  id_token: string
} & Record<string, string | number>

export const GoogleStrategyScopeSeperator = ' '
export const GoogleStrategyDefaultScopes = [
  'openid',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/userinfo.email',
].join(GoogleStrategyScopeSeperator)
export const GoogleStrategyDefaultName = 'google'

export class GoogleStrategy<User> extends OAuth2Strategy<User> {
  public override name = GoogleStrategyDefaultName

  private readonly accessType: string

  private readonly prompt?: 'none' | 'consent' | 'select_account'

  private readonly includeGrantedScopes: boolean

  private readonly hd?: string

  private readonly loginHint?: string

  private readonly userInfoURL = 'https://www.googleapis.com/oauth2/v3/userinfo'

  constructor(
    {
      clientId,
      clientSecret,
      redirectURI,
      scopes,
      accessType,
      includeGrantedScopes,
      prompt,
      hd,
      loginHint,
    }: GoogleStrategyOptions,
    verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>,
  ) {
    super(
      {
        clientId,
        clientSecret,
        redirectURI,
        authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenEndpoint: 'https://oauth2.googleapis.com/token',
        scopes: GoogleStrategy.parseScopes(scopes),
      },
      verify,
    )
    this.accessType = accessType ?? 'online'
    this.includeGrantedScopes = includeGrantedScopes ?? false
    this.prompt = prompt
    this.hd = hd
    this.loginHint = loginHint
  }

  protected override authorizationParams(): URLSearchParams {
    const params = new URLSearchParams({
      access_type: this.accessType,
      include_granted_scopes: String(this.includeGrantedScopes),
    })
    if (this.prompt) {
      params.set('prompt', this.prompt)
    }
    if (this.hd) {
      params.set('hd', this.hd)
    }
    if (this.loginHint) {
      params.set('login_hint', this.loginHint)
    }
    return params
  }

  protected async userProfile(accessToken: string): Promise<GoogleProfile> {
    const response = await fetch(this.userInfoURL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })
    const raw: GoogleProfile['_json'] = await response.json()
    const profile: GoogleProfile = {
      provider: 'google',
      id: raw.sub,
      displayName: raw.name,
      name: {
        familyName: raw.family_name,
        givenName: raw.given_name,
      },
      emails: [{ value: raw.email }],
      photos: [{ value: raw.picture }],
      _json: raw,
    }
    return profile
  }

  // Allow users the option to pass a scope string, or typed array
  public static parseScopes(scopes: GoogleStrategyOptions['scopes']) {
    if (!scopes || scopes.length === 0) {
      return [GoogleStrategyDefaultScopes]
    }

    return scopes
  }
}
