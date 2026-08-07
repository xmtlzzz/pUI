import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { protocolColor, protocolStyle } from '../model/protocolColors'

interface Props {
  title: string
  options: string[]
  current: string[]
  disabled?: boolean
  hint?: string
  /** 协议选项显示颜色点 */
  colorize?: boolean
  onToggle: (value: string) => void
}

// 模块级注册表:同时只允许一个下拉菜单打开
const openClosers = new Set<() => void>()

/** 自定义下拉选择:点选即在 current 中增删,多选式,风格与整体 UI 一致 */
export function FilterSelect({ title, options, current, disabled, hint, colorize, onToggle }: Props) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{ top: number; left: number; width: number; up: boolean } | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const uid = useId()

  // 稳定引用:供 openClosers 注册表比较身份,避免"打开即把自己关掉"
  const close = useCallback(() => setOpen(false), [])

  useEffect(() => {
    openClosers.add(close)
    return () => {
      openClosers.delete(close)
    }
  }, [])

  useEffect(() => {
    if (!open) return
    // 打开时关闭其它下拉(避免堆叠)
    openClosers.forEach((fn) => {
      if (fn !== close) fn()
    })

    const el = triggerRef.current
    if (el) {
      const r = el.getBoundingClientRect()
      const menuH = menuRef.current?.offsetHeight ?? 200
      const spaceBelow = window.innerHeight - r.bottom - 8
      const up = spaceBelow < menuH && r.top > menuH
      setPos({ top: up ? Math.max(8, r.top - menuH - 4) : r.bottom + 4, left: r.left, width: r.width, up })
    }

    const onDown = (e: MouseEvent) => {
      const t = e.target as Node
      if (triggerRef.current?.contains(t)) return
      if (menuRef.current?.contains(t)) return
      setOpen(false)
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

  const toggleOpen = () => {
    if (disabled) return
    if (open) {
      setOpen(false)
    } else {
      openClosers.forEach((fn) => {
        if (fn !== close) fn()
      })
      setOpen(true)
    }
  }

  return (
    <div className={`field${disabled ? ' disabled' : ''}`} title={disabled ? hint : ''}>
      <span className="field-label">{title}</span>
      <button ref={triggerRef} type="button" className="fselect" disabled={disabled} onClick={toggleOpen} aria-haspopup="listbox" aria-expanded={open}>
        <span>{current.length ? `${title} ×${current.length}` : '+ 添加'}</span>
        <span className={`chevron${open ? ' up' : ''}`}>▾</span>
      </button>
      <div className="chips">
        {current.map((v) => {
          const st = colorize ? protocolStyle(v) : { bg: '#eff6ff', fg: '#1d4ed8' }
          return (
            <span key={v} className="badge chip" style={{ background: st.bg, color: st.fg }} onClick={() => onToggle(v)}>
              {v} ✕
            </span>
          )
        })}
      </div>
      {open &&
        pos &&
        createPortal(
          <div ref={menuRef} id={`pui-filter-menu-${uid}`} className={`fmenu${pos.up ? ' up' : ''}`} style={{ top: pos.top, left: pos.left, minWidth: pos.width }} role="listbox">
            {options.map((opt) => (
              <button
                key={opt}
                type="button"
                className={`fitem${current.includes(opt) ? ' on' : ''}`}
                role="option"
                aria-selected={current.includes(opt)}
                onClick={() => onToggle(opt)}
              >
                <span className="check">{current.includes(opt) ? '✓' : ''}</span>
                {colorize && <span className="pdot" style={{ background: protocolColor(opt) }} />}
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
