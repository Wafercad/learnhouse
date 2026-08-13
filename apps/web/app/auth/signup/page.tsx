import { redirect } from 'next/navigation'
import { Metadata } from 'next'

// Self-service signup is disabled on Cloud Campus. Onboarding is invitation/
// credential-based and owned by Wafercad: users are provisioned via the console
// (invite code -> Wafercad account -> SSO hand-off). Any direct hit to
// /auth/signup is bounced to the Wafercad login. The pre-auth course marketing
// lives on the Campus landing, not here. Configurable via NEXT_PUBLIC_WC_LOGIN_URL.
export const metadata: Metadata = {
  title: 'Redirecting to Wafercad…',
  robots: { index: false, follow: false },
}

const WC_LOGIN_URL =
  process.env.NEXT_PUBLIC_WC_LOGIN_URL || 'https://app.wafercad.com/login'

const SignUp = () => {
  redirect(WC_LOGIN_URL)
}

export default SignUp
