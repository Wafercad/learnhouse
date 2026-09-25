'use client'

import { ArrowLeft } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { getWCDashboardUrl } from '@services/config/config'
import { suiteAdminUrl } from '@services/config/suite-navigation'

/** Ordinary same-tab navigation preserves both applications' existing sessions. */
export default function SuiteReturnLink({ isCollapsed }: { isCollapsed: boolean }) {
  const { t } = useTranslation()
  const href = suiteAdminUrl(getWCDashboardUrl())
  if (!href) return null
  const label = t('navigation.back_to_wcs_admin', { defaultValue: 'Back to WCS admin' })
  return (
    <a
      href={href}
      aria-label={label}
      title={label}
      className={`mx-3 mt-3 flex shrink-0 items-center rounded-lg border border-white/20
        bg-white/10 py-2 text-sm font-medium text-white hover:bg-white/20
        focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2
        focus-visible:outline-white ${isCollapsed ? 'justify-center' : 'gap-2 px-3'}`}
    >
      <ArrowLeft size={18} aria-hidden="true" className="shrink-0" />
      {!isCollapsed && <span>{label}</span>}
    </a>
  )
}
