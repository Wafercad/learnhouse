import { redirect } from 'next/navigation'
import { Metadata } from 'next'

// Cloud Campus (LearnHouse) does NOT host its own login. Identity is owned by
// Wafercad — users authenticate in the Wafercad console and reach Campus only via
// the authenticated SSO hand-off (the admin magic-link/magic-consume API route,
// which is unaffected by this). Any direct hit to /auth/login is bounced to the
// Wafercad login. Configurable via NEXT_PUBLIC_WC_LOGIN_URL for each environment.
export const metadata: Metadata = {
  title: 'Redirecting to Wafercad…',
  robots: { index: false, follow: false },
}

const WC_LOGIN_URL =
  process.env.NEXT_PUBLIC_WC_LOGIN_URL || 'https://app.wafercad.com/login'

const Login = () => {
  redirect(WC_LOGIN_URL)
}

export default Login
