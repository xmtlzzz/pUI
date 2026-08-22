import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'
import type { Topology, TopologyEdge, TopologyNode } from '../stats/topology'
import { fmtBytesShort } from './topoUtil'

/** 生成始终面向相机的文字标签(canvas 2d 不可用时返回 null,jsdom 降级) */
export function makeHostLabel(text: string): THREE.Sprite | null {
  const canvas = document.createElement('canvas')
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  const font = '600 13px system-ui, sans-serif'
  // 先在 2x 分辨率下测量,再建画布(设置 canvas 尺寸会重置上下文)——
  // 顺序错误会导致字体回退到默认 10px,长主机名被截断
  ctx.font = font
  const w = Math.max(48, Math.ceil(ctx.measureText(text).width / 2) + 18)
  const h = 18
  canvas.width = w * 2
  canvas.height = h * 2
  ctx.font = font
  ctx.fillStyle = '#0f172a'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillText(text, canvas.width / 2, canvas.height / 2)
  const texture = new THREE.CanvasTexture(canvas)
  const mat = new THREE.SpriteMaterial({ map: texture, transparent: true, depthTest: true })
  const sprite = new THREE.Sprite(mat)
  sprite.scale.set(w / 4, h / 4, 1)
  return sprite
}

/*** 3D 拓扑视图(three.js):球面分布式节点 + 文字标签 + 连线,
 *  OrbitControls 旋转/缩放;点击节点选中其首个会话。WebGL 不可用时降级提示。 */
export function Topology3D({ topo, onSelectConversation }: { topo: Topology; onSelectConversation?: (convId: string) => void }) {
  const mountRef = useRef<HTMLDivElement | null>(null)
  const [webgl, setWebgl] = useState<boolean | null>(null)

  useEffect(() => {
    const mount = mountRef.current
    if (!mount) return
    const probe = document.createElement('canvas')
    const gl = probe.getContext('webgl2') ?? probe.getContext('webgl')
    if (!gl) {
      setWebgl(false)
      return
    }
    setWebgl(true)

    const width = mount.clientWidth || 600
    const height = mount.clientHeight || 420
    const renderer = new THREE.WebGLRenderer({ antialias: true })
    renderer.setSize(width, height)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
    renderer.outputColorSpace = THREE.SRGBColorSpace
    mount.appendChild(renderer.domElement)

    const scene = new THREE.Scene()
    scene.background = new THREE.Color('#f8fafc')
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 2000)
    camera.position.set(0, 90, 240)
    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.autoRotate = true
    controls.autoRotateSpeed = 0.6

    const ambient = new THREE.AmbientLight('#ffffff', 0.9)
    scene.add(ambient)
    const dir = new THREE.DirectionalLight('#ffffff', 1.2)
    dir.position.set(60, 120, 80)
    scene.add(dir)

    const group = new THREE.Group()
    scene.add(group)

    // 球面分布节点 + 文字标签(jsdom 无 2d → null 跳过)
    const n = topo.nodes.length
    const radius = Math.min(150, Math.max(60, n * 14))
    const posMap = new Map<string, THREE.Vector3>()
    const meshByHost = new Map<string, THREE.Mesh>()
    topo.nodes.forEach((node: TopologyNode, i: number) => {
      const phi = Math.acos(1 - (2 * (i + 0.5)) / Math.max(n, 1))
      const theta = Math.sqrt(Math.PI * n) * phi
      const pos = new THREE.Vector3(
        radius * Math.cos(theta) * Math.sin(phi),
        radius * Math.cos(phi),
        radius * Math.sin(theta) * Math.sin(phi),
      )
      posMap.set(node.id, pos)
      const r = 4 + (node.conversations / Math.max(...topo.nodes.map((x) => x.conversations), 1)) * 8
      const geo = new THREE.SphereGeometry(r, 24, 24)
      const mat = new THREE.MeshStandardMaterial({
        color: node.issues ? '#ea580c' : '#2563eb',
        roughness: 0.35,
      })
      const mesh = new THREE.Mesh(geo, mat)
      mesh.position.copy(pos)
      mesh.userData.title = node.host
      mesh.userData.hostId = node.id
      group.add(mesh)
      meshByHost.set(node.id, mesh)
      const label = makeHostLabel(node.host)
      if (label) {
        label.position.set(pos.x, pos.y + r + 7, pos.z)
        label.userData.hostId = node.id
        group.add(label)
      }
    })

    // 连线:异常橙色,WebGL 线宽恒 1(粗细表达在 2D 视图)
    const edges = topo.edges.filter((e) => posMap.has(e.from) && posMap.has(e.to))
    edges.forEach((e: TopologyEdge) => {
      const a = posMap.get(e.from)!
      const b = posMap.get(e.to)!
      const geo = new THREE.BufferGeometry().setFromPoints([a, b])
      const mat = new THREE.LineBasicMaterial({
        color: e.hasIssue ? '#f59e0b' : '#94a3b8',
      })
      const line = new THREE.Line(geo, mat)
      line.userData.title = `${e.from} ⇄ ${e.to} · ${fmtBytesShort(e.bytes)}${e.hasIssue ? ' · ⚠异常' : ''}`
      group.add(line)
    })

    const raycaster = new THREE.Raycaster()
    const pointer = new THREE.Vector2()
    const meshes = Array.from(meshByHost.values())
    const pick = (ev: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1
      pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1
      raycaster.setFromCamera(pointer, camera)
      return raycaster.intersectObjects(meshes, false)
    }
    const onMove = (ev: PointerEvent) => {
      const hits = pick(ev)
      if (hits.length) {
        renderer.domElement.style.cursor = 'pointer'
        renderer.domElement.title = String(hits[0].object.userData.title ?? '')
      } else {
        renderer.domElement.style.cursor = 'grab'
        renderer.domElement.title = ''
      }
    }
    const onClick = (ev: Event) => {
      const hits = pick(ev as PointerEvent)
      if (!hits.length || !onSelectConversation) return
      const hostId = hits[0].object.userData.hostId as string | undefined
      if (!hostId) return
      // 选中该主机参与的第一条边对应的会话(与 2D 拓扑的点击语义对齐)
      const edge = edges.find((e) => e.from === hostId || e.to === hostId)
      if (edge) onSelectConversation(edge.convIds[0])
    }
    renderer.domElement.addEventListener('pointermove', onMove)
    renderer.domElement.addEventListener('click', onClick)

    const onResize = () => {
      const w = mount.clientWidth || width
      const h = mount.clientHeight || height
      renderer.setSize(w, h)
      camera.aspect = w / h
      camera.updateProjectionMatrix()
    }
    const ro = new ResizeObserver(onResize)
    ro.observe(mount)

    let raf = 0
    const animate = () => {
      controls.update()
      renderer.render(scene, camera)
      raf = requestAnimationFrame(animate)
    }
    animate()

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
      renderer.domElement.removeEventListener('pointermove', onMove)
      renderer.domElement.removeEventListener('click', onClick)
      renderer.dispose()
      controls.dispose()
      group.clear()
      if (renderer.domElement.parentNode === mount) mount.removeChild(renderer.domElement)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topo])

  if (webgl === false) {
    return <div className="empty">3D 视图需要 WebGL,当前环境不可用(已在 2D 拓扑中降级)</div>
  }
  return <div ref={mountRef} className="topo3d" />
}