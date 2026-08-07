import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

interface Props {
  title: string
  options: string[]
  current: string[]
  disabled?: boolean
  hint?: string
  onToggle: (value: string) => void
}

/** 自定义下拉选择:点选即在 current 中增删,多选式,风格与整体 UI 一致 */
export function FilterSelect({ title, options, current, disabled, hint, onToggle }: Props) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{ top: number; left: number; width: number } | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const el = triggerRef.current
    if (el) {
      const r = el.getBoundingClientRect()
      setPos({ top: r.bottom + 4, left: r.left, width: r.width })
    }
    const onDown = (e: MouseEvent) => {
      const menu = document.getElementById('pui-filter-menu')
      if (!triggerRef.current?.contains(e.target as Node) && !menu?.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onEsc)
    }
  }, [open])

  return (
    <div className={`field${disabled ? ' disabled' : ''}`} title={disabled ? hint : ''}>
      <span className="field-label">{title}</span>
      <button
        ref={triggerRef}
        type="button"
        className="fselect"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span>{current.length ? `${title} ×${current.length}` : '+ 添加'}</span>
        <span className={`chevron${open ? ' up' : ''}`}>▾</span>
      </button>
      <div className="chips">
        {current.map((v) => (
          <span key={v} className="badge chip" onClick={() => onToggle(v)}>
            {v} ✕
          </span>
        ))}
      </div>
      {open &&
        pos &&
        createPortal(
          <div id="pui-filter-menu" className="fmenu" style={{ top: pos.top, left: pos.left, minWidth: pos.width }} role="listbox">
            {options.map((opt) => (
              <button key={opt} type="button" className={`fitem${current.includes(opt) ? ' on' : ''}`} role="option" aria-selected={current.includes(opt)} onClick={() => onToggle(opt)}>
                <span className="check">{current.includes(opt) ? '✓' : ''}</span>
                <span className="fitem-label">{opt}</span>
              </button>
            ))}
            {!options.length && <div className="fmenu-empty">无可选项</div>}
          </div>,
          document.body,
        )}
    </div>
  )
}
