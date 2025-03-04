# @curvenote/remix-auth-google

**Forked** and updated from [https://github.com/pbteja1998/remix-auth-google](https://github.com/pbteja1998/remix-auth-google) to use the latest `remix-auth-oauth2` strategy.

<!-- Description -->

The Google strategy is used to authenticate users against a Google account. It extends the OAuth2Strategy.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

<!-- If it doesn't support one runtime, explain here why -->

## Usage

### Create an OAuth application

Follow the steps on [the Google documentation](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred) to create a new application and get a client ID and secret.

### Create the strategy instance

```ts
// app/services/auth.server.ts
import { GoogleStrategy } from 'remix-auth-google'

let googleStrategy = new GoogleStrategy(
  {
    clientID: 'YOUR_CLIENT_ID',
    clientSecret: 'YOUR_CLIENT_SECRET',
    callbackURL: 'https://example.com/auth/google/callback',
  },
  async ({ accessToken, refreshToken, extraParams, profile }) => {
    // Get the user data from your DB or API using the tokens and profile
    return User.findOrCreate({ email: profile.emails[0].value })
  },
)

authenticator.use(googleStrategy)
```

### Setup your routes

```tsx
// app/routes/login.tsx
export default function Login() {
  return (
    <Form action="/auth/google" method="post">
      <button>Login with Google</button>
    </Form>
  )
}
```

```tsx
// app/routes/auth.google.tsx
import { redirect, type ActionFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/services/auth.server'

export let loader = () => redirect('/login')

export let action = ({ request }: ActionFunctionArgs) => {
  return authenticator.authenticate('google', request)
}
```

```tsx
// app/routes/auth.google.callback.tsx
import type { LoaderFunctionArgs } from '@remix-run/node'
import { authenticator } from '~/services/auth.server'

export let loader = ({ request }: LoaderFunctionArgs) => {
  return authenticator.authenticate('google', request, {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
  })
}
```
