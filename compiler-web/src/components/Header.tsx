import { SignOut, UserCircle } from '@phosphor-icons/react'

interface HeaderProps {
  pubkey?: string
  displayName?: string
  listName?: string
  onLogin: () => void
  onLogout: () => void
}

export function Header({ pubkey, displayName, listName, onLogin, onLogout }: HeaderProps) {
  return (
    <header className="app-header">
      <div className="brand-lockup">
        <span className="brand-word">divine</span>
        <span className="brand-product">compiler</span>
      </div>
      <div className="header-context">
        {listName && <span className="header-list">{listName}</span>}
        {pubkey ? (
          <button className="identity-button" type="button" onClick={onLogout}>
            <UserCircle size={20} weight="fill" />
            <span>{displayName ?? `${pubkey.slice(0, 8)}…${pubkey.slice(-6)}`}</span>
            <SignOut size={16} />
          </button>
        ) : (
          <button className="button primary compact" type="button" onClick={onLogin}>
            Connect Divine
          </button>
        )}
      </div>
    </header>
  )
}
