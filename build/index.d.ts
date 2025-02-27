import { OAuth2Strategy } from 'remix-auth-oauth2';
import type { Strategy } from 'remix-auth/strategy';
import type { GoogleStrategyOptions, GoogleScope, GoogleProfile } from './types.js';
export * from './types.js';
export declare const GoogleStrategyScopeSeperator = " ";
export declare const GoogleStrategyDefaultScopes: string;
export declare const GoogleStrategyDefaultName = "google";
export declare class GoogleStrategy<User> extends OAuth2Strategy<User> {
    static userInfoURL: string;
    name: string;
    private readonly accessType;
    private readonly prompt?;
    private readonly includeGrantedScopes;
    private readonly hd?;
    private readonly loginHint?;
    private readonly responseType;
    constructor({ clientId, clientSecret, redirectURI, scopes, accessType, includeGrantedScopes, prompt, hd, loginHint, }: GoogleStrategyOptions, verify: Strategy.VerifyFunction<User, OAuth2Strategy.VerifyOptions>);
    protected authorizationParams(params: URLSearchParams, request: Request): URLSearchParams;
    protected stringifyScopes(scopes: GoogleScope[]): string;
    static userProfile(accessToken: string): Promise<GoogleProfile>;
    static parseScopes(scopes: GoogleStrategyOptions['scopes']): string[];
}
