import { useEffect, useRef, useState } from 'react'

/** Counts up from 0 to `value` on mount / value change. Subtle, ~700ms ease-out. */
export default function AnimatedNumber({ value, duration = 700, decimals = 0, suffix = '' }) {
  const [display, setDisplay] = useState(0)
  const frame = useRef()

  useEffect(() => {
    const target = Number(value) || 0
    const start = performance.now()
    const from = 0
    cancelAnimationFrame(frame.current)

    function tick(now) {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(from + (target - from) * eased)
      if (t < 1) frame.current = requestAnimationFrame(tick)
      else setDisplay(target)
    }
    frame.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame.current)
  }, [value, duration])

  return <>{display.toFixed(decimals)}{suffix}</>
}
