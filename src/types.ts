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
