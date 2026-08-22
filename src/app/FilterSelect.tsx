import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent } from 'react'
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
  // 键盘高亮位(0..options.length-1),null 表示未高亮;焦点始终留在 trigger 上
  const [activeIdx, setActiveIdx] = useState<number | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const uid = useId()
  // 同步镜像 open,供同一次事件里读取最新值(React 状态更新是异步的)
  const openRef = useRef(open)
  openRef.current = open

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
    const onEsc = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
      // Tab 移出时关闭菜单:焦点不在菜单内还保持打开,纯键盘用户会迷失焦点归属
      if (e.key === 'Tab') setOpen(false)
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

  // 键盘导航:↑/↓ 循环高亮(关闭时自动打开),Enter 切换高亮项,焦点始终在 trigger 上
  const onTriggerKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      if (!openRef.current) {
        openClosers.forEach((fn) => {
          if (fn !== close) fn()
        })
        setOpen(true)
      }
      const dir = e.key === 'ArrowDown' ? 1 : -1
      setActiveIdx((prev) => {
        const n = options.length
        if (!n) return null
        const base = prev == null ? (dir === 1 ? -1 : 0) : prev
        return (base + dir + n) % n
      })
    } else if (e.key === 'Enter') {
      // 菜单已打开且有高亮项 → 切换该选项(多选,保持打开);否则走按钮默认行为(开/关菜单)
      if (openRef.current && activeIdx != null && options[activeIdx] != null) {
        e.preventDefault()
        onToggle(options[activeIdx])
      }
    } else if (e.key === 'Escape') {
      setOpen(false)
    }
  }

  return (
    <div className={`field${disabled ? ' disabled' : ''}`} title={disabled ? hint : ''}>
      <span className="field-label">{title}</span>
      <button
        ref={triggerRef}
        type="button"
        className="fselect"
        disabled={disabled}
        onClick={toggleOpen}
        onKeyDown={onTriggerKeyDown}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-activedescendant={open && activeIdx != null ? `pui-opt-${uid}-${activeIdx}` : undefined}
      >
        <span>{current.length ? `${title} ×${current.length}` : '+ 添加'}</span>
        <span className={`chevron${open ? ' up' : ''}`}>▾</span>
      </button>
      <div className="chips">
        {current.map((v) => {
          const st = colorize ? protocolStyle(v) : { bg: '#eff6ff', fg: '#1d4ed8' }
          return (
            <button key={v} type="button" className="badge chip" style={{ background: st.bg, color: st.fg }} onClick={() => onToggle(v)} aria-label={`移除 ${v}`}>
              {v} ✕
            </button>
          )
        })}
      </div>
      {open &&
        pos &&
        createPortal(
          <div ref={menuRef} id={`pui-filter-menu-${uid}`} className={`fmenu${pos.up ? ' up' : ''}`} style={{ top: pos.top, left: pos.left, minWidth: pos.width }} role="listbox">
            {options.map((opt, i) => (
              <button
                key={opt}
                id={`pui-opt-${uid}-${i}`}
                type="button"
                className={`fitem${current.includes(opt) ? ' on' : ''}${activeIdx === i ? ' active' : ''}`}
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
