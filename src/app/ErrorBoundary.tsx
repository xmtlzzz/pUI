import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  /** 边界名称,显示在错误面板里便于定位 */
  name: string
  children: ReactNode
}

interface State {
  error: Error | null
}

/** 渲染错误边界:子组件崩溃时显示可读错误而非整窗白屏;点击「重试」重新挂载子树 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // 保留完整堆栈到控制台,便于上报;界面只展示可读信息
    console.error(`[${this.props.name}] 渲染失败:`, error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="boundary-err" role="alert">
          <div className="boundary-title">⚠ {this.props.name}渲染出错</div>
          <div className="boundary-msg">
            {String(this.state.error.message || this.state.error)}
          </div>
          <button
            type="button"
            className="btn"
            onClick={() => this.setState({ error: null })}
          >
            重试
          </button>
        </div>
      )
    }
    return this.props.children
  }
}