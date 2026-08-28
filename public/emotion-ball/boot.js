/* pUI × emotion-ball 启动屏接入层。
 * 引擎本体(rings/emotions/ball/engine.js)原样来自官方仓库,本文件只做创建与销毁:
 *   https://github.com/sam70361/aora-bot (emotion-ball/js/)
 * 许可:引擎个人学习研究免费,商用需 LICENSE-COMMERCIAL 授权;
 * 球形角色视觉形象仅限个人学习研究 —— 见同目录 NOTICE.md。 */
(function () {
  'use strict'
  function boot() {
    var mount = document.getElementById('boot-ball')
    // 启动诊断:bundle 加载/执行失败时,启动屏直接显示原因(而非无声卡死)。
    // 走外部脚本(本文件),生产 CSP script-src 'self' 允许
    var sub = document.querySelector('#boot .boot-sub')
    function fail(msg) {
      if (sub) sub.textContent = '启动出错: ' + msg
    }
    window.addEventListener('error', function (e) {
      if (document.getElementById('boot')) fail((e && e.message) || '脚本加载失败')
    })
    window.addEventListener('unhandledrejection', function (e) {
      if (document.getElementById('boot')) fail(String((e && e.reason && e.reason.message) || e.reason || 'promise 异常'))
    })
    if (!mount || typeof window.EmotionBall === 'undefined') return
    try {
      var ball = window.EmotionBall.create(mount, {
        emotion: '36', // 联网加载(表情库 id 30-49 = 代理状态段)
        idle: true,
      })
      // tips 文案同步到底部小字(引擎 emit,避免自己改 DOM 时序)
      var tipsEl = document.querySelector('#boot .boot-sub')
      window.EmotionBall.__pui = ball
      ball.on('tips', function (e) {
        if (tipsEl && e && e.text) tipsEl.textContent = String(e.text)
      })
      // 销毁钩子:React 挂载后由 main.tsx 调用,停掉引擎 RAF 再移除节点
      window.__puiBootTeardown = function () {
        try {
          ball.destroy()
        } catch (e) {
          /* 引擎销毁失败不阻塞启动层移除 */
        }
        window.EmotionBall.__pui = null
      }
    } catch (e) {
      // 引擎不可用(脚本加载失败等):保持纯文字加载层,不阻塞启动
      if (window.console && console.warn) console.warn('[pUI] emotion-ball 启动屏不可用:', e)
    }
  }
  boot()
})()
