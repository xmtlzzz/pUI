/** 绝对时间戳格式化:epoch 秒 → 本地 HH:MM:SS.mmm */
export function formatEpoch(epochSec: number): string {
  const d = new Date(epochSec * 1000)
  const pad = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}
