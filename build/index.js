import { OAuth2Strategy } from 'remix-auth-oauth2';
export * from './types.js';
export const GoogleStrategyScopeSeperator = ' ';
export const GoogleStrategyDefaultScopes = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
].join(GoogleStrategyScopeSeperator);
export const GoogleStrategyDefaultName = 'google';
export class GoogleStrategy extends OAuth2Strategy {
    static userInfoURL = 'https://www.googleapis.com/oauth2/v3/userinfo';
    name = GoogleStrategyDefaultName;
    accessType;
    prompt;
    includeGrantedScopes;
    hd;
    loginHint;
    responseType;
    constructor({ clientId, clientSecret, redirectURI, scopes, accessType, includeGrantedScopes, prompt, hd, loginHint, }, verify) {
        super({
            cookie: {
                name: 'google-oauth2',
            },
            clientId,
            clientSecret,
            redirectURI,
            authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenEndpoint: 'https://oauth2.googleapis.com/token',
            scopes: GoogleStrategy.parseScopes(scopes),
        }, verify);
        this.responseType = 'code';
        this.accessType = accessType ?? 'online';
        this.includeGrantedScopes = includeGrantedScopes ?? false;
        this.prompt = prompt;
        this.hd = hd;
        this.loginHint = loginHint;
    }
    authorizationParams(params, 
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    request) {
        // pass through on existing params allows for state to flow through
        const newParams = new URLSearchParams(params);
        newParams.set('access_type', this.accessType);
        newParams.set('include_granted_scopes', String(this.includeGrantedScopes));
        if (this.options.clientId) {
            newParams.set('client_id', this.client.clientId);
        }
        if (this.options.scopes) {
            newParams.set('scope', this.stringifyScopes(this.options.scopes));
        }
        if (this.options.redirectURI) {
            newParams.set('redirect_uri', typeof this.options.redirectURI === 'string'
                ? this.options.redirectURI
                : this.options.redirectURI.toString());
        }
        if (this.responseType) {
            newParams.set('response_type', this.responseType);
        }
        if (this.prompt) {
            newParams.set('prompt', this.prompt);
        }
        if (this.hd) {
            newParams.set('hd', this.hd);
        }
        if (this.loginHint) {
            newParams.set('login_hint', this.loginHint);
        }
        return newParams;
    }
    stringifyScopes(scopes) {
        return scopes.join(GoogleStrategyScopeSeperator);
    }
    static async userProfile(accessToken) {
        const response = await fetch(GoogleStrategy.userInfoURL, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
        const raw = await response.json();
        const profile = {
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
        };
        return profile;
    }
    // Allow users the option to pass a scope string, or typed array
    static parseScopes(scopes) {
        if (!scopes || scopes.length === 0) {
            return [GoogleStrategyDefaultScopes];
        }
        return scopes;
    }
}
//# sourceMappingURL=index.js.map