import React, { useState, useMemo, useRef, useEffect } from 'react';
import { useAnalysis } from '../AnalysisContext';
import { Network } from 'lucide-react';

interface NodePos {
  id: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  weight: number;
  column: 'left' | 'right';
}

interface PathLink {
  id: string;
  sourceId: string;
  targetId: string;
  sourceLabel: string;
  targetLabel: string;
  protocolBreakdown: string;
  value: number;
  rawBits: number;
  sy: number;
  ty: number;
  h: number;
  path: string;
}

export function TopTalkersSankey() {
  const { result } = useAnalysis();
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredLink, setHoveredLink] = useState<string | null>(null);
  const [activeTooltip, setActiveTooltip] = useState<{ text: string; x: number; y: number } | null>(null);
  
  const [scrollTop, setScrollTop] = useState<number>(0);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const dragStartY = useRef<number>(0);
  const dragStartScrollTop = useRef<number>(0);

  const colorPalette = useMemo(() => [
    '#3b82f6', '#10b981', '#6366f1', '#f59e0b', '#ec4899', 
    '#14b8a6', '#8b5cf6', '#f43f5e', '#06b6d4', '#10b981'
  ], []);

  const formatBitsVolume = (bits: number) => {
    if (!bits || isNaN(bits) || bits <= 0) {
      return '0 b';
    }
    const k = 1000;
    const sizes = ['b', 'Kb', 'Mb', 'Gb', 'Tb'];
    const i = Math.floor(Math.log(bits) / Math.log(k));
    const safeIndex = Math.min(Math.max(i, 0), sizes.length - 1);
    return parseFloat((bits / Math.pow(k, safeIndex)).toFixed(2)) + ' ' + sizes[safeIndex];
  };

  const visibleHeight = 440; 
  const virtualCanvasHeight = 800; 
  const maxScroll = virtualCanvasHeight - visibleHeight;

  const sankeyData = useMemo(() => {
    if (!result || !result.rows || result.rows.length === 0) {
      return { nodes: [], links: [], linkColors: {} };
    }

    const rows = result.rows;
    const linkMap = new Map<string, { sourceId: string; targetId: string; sourceLabel: string; targetLabel: string; totalBits: number; protocols: Record<string, number> }>();

    rows.forEach(row => {
      const src = row['Src IP'] || 'N/A';
      const dst = row['Dst IP'] || 'N/A';
      const proto = row['Protocol'] || 'OTHER';
      
      let bytes = Number(row['Bytes']);
      if (isNaN(bytes) || bytes === undefined) {
        const throughput = Number(row['Throughput (Mbps)']) || 0;
        const duration = Number(row['Flow Duration (ms)']) || 1000;
        bytes = (throughput * 125000) * (duration / 1000);
      }

      const bits = bytes * 8;
      const srcId = `src_${src}`;
      const dstId = `dst_${dst}`;
      const pairKey = `${srcId}||${dstId}`;

      const existing = linkMap.get(pairKey) || { 
        sourceId: srcId,
        targetId: dstId,
        sourceLabel: String(src).trim(),
        targetLabel: String(dst).trim(),
        totalBits: 0, 
        protocols: {} 
      };
      
      existing.totalBits += bits;
      existing.protocols[proto] = (existing.protocols[proto] || 0) + bits;
      linkMap.set(pairKey, existing);
    });

    const rawLinks = Array.from(linkMap.values()).map((data) => {
      const sortedProtos = Object.entries(data.protocols).sort((a, b) => b[1] - a[1]);
      const linkKb = data.totalBits / 1000;
      
      const breakdownStr = sortedProtos
        .slice(0, 3)
        .map(([protoName, protoVal]) => `${protoName}: ${formatBitsVolume(protoVal)}`)
        .join(' | ');

      return { 
        sourceId: data.sourceId, 
        targetId: data.targetId, 
        sourceLabel: data.sourceLabel || 'N/A', 
        targetLabel: data.targetLabel || 'N/A', 
        protocolBreakdown: breakdownStr, 
        value: linkKb,
        rawBits: data.totalBits
      };
    });

    rawLinks.sort((a, b) => b.value - a.value);
    const topLinks = rawLinks.slice(0, 10);

    const activeNodeIds = new Set<string>();
    topLinks.forEach(l => {
      activeNodeIds.add(l.sourceId);
      activeNodeIds.add(l.targetId);
    });

    const tempNodes: Record<string, { id: string; label: string; weight: number; rawBits: number; column: 'left' | 'right' }> = {};

    activeNodeIds.forEach(id => {
      let label = id;
      let column: 'left' | 'right' = 'left';

      if (id.startsWith('src_')) {
        label = id.substring(4);
        column = 'left';
      } else if (id.startsWith('dst_')) {
        label = id.substring(4);
        column = 'right';
      }

      tempNodes[id] = { id, label, weight: 0, rawBits: 0, column };
    });

    topLinks.forEach(link => {
      if (tempNodes[link.sourceId]) {
        tempNodes[link.sourceId].weight += link.value;
        tempNodes[link.sourceId].rawBits += link.rawBits;
      }
      if (tempNodes[link.targetId]) {
        tempNodes[link.targetId].weight += link.value;
        tempNodes[link.targetId].rawBits += link.rawBits;
      }
    });

    const leftNodes = Object.values(tempNodes).filter(n => n.column === 'left').sort((a, b) => b.weight - a.weight);
    const rightNodes = Object.values(tempNodes).filter(n => n.column === 'right').sort((a, b) => b.weight - a.weight);

    const colLeftX = 140;
    const colRightX = 924;
    const nodeW = 16;
    const minNodeHeight = 28;
    const nodeSpacing = 28;
    const paddingY = 24;

    const arrangeColumnNodes = (colNodes: typeof leftNodes, xCoord: number, colKey: 'left' | 'right', currentSvgH: number) => {
      if (colNodes.length === 0) return [];
      
      const totalColWeight = colNodes.reduce((sum, n) => sum + n.weight, 0);
      const totalSpacing = (colNodes.length - 1) * nodeSpacing;
      const hAvail = currentSvgH - (paddingY * 2) - totalSpacing - 40;

      let currentY = paddingY;

      return colNodes.map(n => {
        const hPercent = totalColWeight > 0 ? (n.weight / totalColWeight) : (1 / colNodes.length);
        const h = Math.max(minNodeHeight, hPercent * hAvail);
        const node: NodePos & { rawBits: number } = {
          id: n.id,
          label: n.label,
          x: xCoord,
          y: currentY,
          width: nodeW,
          height: h,
          weight: n.weight,
          rawBits: n.rawBits,
          column: colKey
        };
        currentY += h + nodeSpacing;
        return node;
      });
    };

    const finalNodesMap: Record<string, NodePos & { rawBits: number }> = {};
    const finalNodes = [
      ...arrangeColumnNodes(leftNodes, colLeftX, 'left', virtualCanvasHeight),
      ...arrangeColumnNodes(rightNodes, colRightX, 'right', virtualCanvasHeight)
    ];

    finalNodes.forEach(node => {
      finalNodesMap[node.id] = node;
    });

    const srcRunningOffsets: Record<string, number> = {};
    const dstRunningOffsets: Record<string, number> = {};
    const finalLinks: PathLink[] = [];
    const linkColors: Record<string, string> = {};

    topLinks.forEach((link, idx) => {
      const srcNode = finalNodesMap[link.sourceId];
      const dstNode = finalNodesMap[link.targetId];

      if (!srcNode || !dstNode) return;

      const linkId = `link_${idx}`;
      const srcOffset = srcRunningOffsets[link.sourceId] || 0;
      const dstOffset = dstRunningOffsets[link.targetId] || 0;

      const srcWeightRatio = srcNode.weight > 0 ? (link.value / srcNode.weight) : 1;
      const dstWeightRatio = dstNode.weight > 0 ? (link.value / dstNode.weight) : 1;

      const linkH = Math.min(srcNode.height * srcWeightRatio, dstNode.height * dstWeightRatio, srcNode.height, dstNode.height);
      const sy = srcNode.y + srcOffset;
      const ty = dstNode.y + dstOffset;

      srcRunningOffsets[link.sourceId] = srcOffset + linkH;
      dstRunningOffsets[link.targetId] = dstOffset + linkH;

      const x0 = srcNode.x + srcNode.width;
      const x1 = dstNode.x;
      const ctrlX = x0 + (x1 - x0) * 0.45;

      const pathString = `
        M ${x0} ${sy}
        C ${ctrlX} ${sy}, ${x1 - ctrlX} ${ty}, ${x1} ${ty}
        v ${linkH}
        C ${x1 - ctrlX} ${ty + linkH}, ${ctrlX} ${sy + linkH}, ${x0} ${sy + linkH}
        Z
      `;

      finalLinks.push({
        id: linkId,
        sourceId: link.sourceId,
        targetId: link.targetId,
        sourceLabel: link.sourceLabel,
        targetLabel: link.targetLabel,
        protocolBreakdown: link.protocolBreakdown,
        value: link.value,
        rawBits: link.rawBits,
        sy,
        ty,
        h: linkH,
        path: pathString
      });

      linkColors[linkId] = colorPalette[idx % colorPalette.length];
    });

    return { nodes: finalNodes, links: finalLinks, linkColors };
  }, [result, colorPalette]);

  const handleWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    e.preventDefault();
    setScrollTop(prev => Math.min(Math.max(prev + e.deltaY * 0.75, 0), maxScroll));
  };

  const handleThumbMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
    dragStartY.current = e.clientY;
    dragStartScrollTop.current = scrollTop;
  };

  useEffect(() => {
    const handleMouseMoveGlobal = (e: MouseEvent) => {
      if (!isDragging) return;
      const deltaY = e.clientY - dragStartY.current;
      const scrollRatio = maxScroll / (visibleHeight - 60); 
      setScrollTop(Math.min(Math.max(dragStartScrollTop.current + deltaY * scrollRatio, 0), maxScroll));
    };

    const handleMouseUpGlobal = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMoveGlobal);
      window.addEventListener('mouseup', handleMouseUpGlobal);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMoveGlobal);
      window.removeEventListener('mouseup', handleMouseUpGlobal);
    };
  }, [isDragging, scrollTop, maxScroll]);

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>, text: string) => {
    const x = e.nativeEvent.offsetX + 15;
    const y = e.nativeEvent.offsetY - 15;
    setActiveTooltip({ text, x, y });
  };

  const thumbHeight = Math.max((visibleHeight / virtualCanvasHeight) * visibleHeight, 40);
  const thumbTop = (scrollTop / maxScroll) * (visibleHeight - thumbHeight);

  if (!result || result.rows.length === 0) {
    return (
      <div className="bg-white border rounded-xl p-16 text-center flex flex-col items-center justify-center space-y-3 shadow-sm">
        <div>
          <h4 className="text-xs font-black text-gray-800 uppercase tracking-widest">Awaiting Session Stream</h4>
          <p className="text-[10px] text-gray-400 font-bold uppercase tracking-wider mt-1">Start capture to map active client traffic allocation pathways.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-sm space-y-4 relative font-sans w-full h-full flex flex-col justify-between">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-blue-50 rounded text-blue-600">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-black text-gray-900 uppercase tracking-widest">Top Talkers</h3>
            <p className="text-[10px] text-gray-400 font-bold uppercase tracking-wider mt-0.5">Session Traffic Allocation: Accumulated Bits Transferred</p>
          </div>
        </div>
      </div>

      <div 
        className="relative bg-gray-50/50 rounded-lg border border-gray-100 p-0 w-full flex-1 overflow-hidden select-none flex"
        style={{ height: `${visibleHeight}px` }}
        onWheel={handleWheel}
      >
        <div className="flex-1 overflow-hidden relative h-full">
          <svg 
            viewBox={`0 0 1080 ${visibleHeight}`} 
            className="w-full h-full overflow-visible block" 
            onMouseLeave={() => { setHoveredLink(null); setHoveredNode(null); setActiveTooltip(null); }}
            style={{ height: `${visibleHeight}px` }}
          >
            <g transform={`translate(0, -${scrollTop})`}>
              {sankeyData.links.map(link => {
                const isLinkNodeActive = hoveredNode ? link.sourceId === hoveredNode || link.targetId === hoveredNode : true;
                const isLinkActive = hoveredLink ? link.id === hoveredLink : true;
                const isActive = isLinkNodeActive && isLinkActive;
                const baseColor = sankeyData.linkColors[link.id] || '#cbd5e1';

                const tooltipLabel = `${link.sourceLabel} → ${link.targetLabel} | Total: ${formatBitsVolume(link.rawBits)} (${link.protocolBreakdown})`;

                return (
                  <g key={link.id}>
                    <defs>
                      <linearGradient id={`grad-${link.id}`} x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor={baseColor} stopOpacity={isActive ? 0.65 : 0.08} />
                        <stop offset="100%" stopColor={baseColor} stopOpacity={isActive ? 0.45 : 0.05} />
                      </linearGradient>
                    </defs>
                    <path
                      d={link.path}
                      fill={`url(#grad-${link.id})`}
                      className="transition-all duration-200 cursor-crosshair"
                      onMouseEnter={(e) => {
                        setHoveredLink(link.id);
                        handleMouseMove(e, tooltipLabel);
                      }}
                      onMouseMove={(e) => {
                        handleMouseMove(e, tooltipLabel);
                      }}
                      onMouseLeave={() => {
                        setHoveredLink(null);
                        setActiveTooltip(null);
                      }}
                    />
                  </g>
                );
              })}

              {sankeyData.nodes.map((node: any) => {
                const isNodeHovered = hoveredNode ? node.id === hoveredNode : true;
                const isLinkConnected = hoveredLink 
                  ? !!sankeyData.links.find(l => l.id === hoveredLink && (l.sourceId === node.id || l.targetId === node.id)) 
                  : true;
                const isActive = isNodeHovered && isLinkConnected;
                const isLeft = node.column === 'left';

                return (
                  <g key={node.id}>
                    <rect
                      x={node.x}
                      y={node.y}
                      width={node.width}
                      height={node.height}
                      rx={3}
                      className="fill-slate-700 stroke-slate-800 transition-all duration-200 cursor-pointer"
                      opacity={isActive ? 1 : 0.25}
                      onMouseEnter={(e) => {
                        setHoveredNode(node.id);
                        handleMouseMove(e, `${node.label} | Total Session Volume: ${formatBitsVolume(node.rawBits)}`);
                      }}
                      onMouseMove={(e) => {
                        handleMouseMove(e, `${node.label} | Total Session Volume: ${formatBitsVolume(node.rawBits)}`);
                      }}
                      onMouseLeave={() => {
                        setHoveredNode(null);
                        setActiveTooltip(null);
                      }}
                    />
                    <text
                      x={isLeft ? node.x - 12 : node.x + node.width + 12}
                      y={node.y + (node.height / 2) + 3.5}
                      textAnchor={isLeft ? 'end' : 'start'}
                      className={`text-[11px] font-mono font-bold transition-all duration-200 ${isActive ? 'fill-gray-900 font-extrabold' : 'fill-gray-400'}`}
                    >
                      {node.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        <div className="w-2.5 border-l border-gray-200 bg-gray-100 h-full relative flex-shrink-0 select-none z-30">
          <div
            onMouseDown={handleThumbMouseDown}
            className={`w-full rounded-sm absolute left-0 transition-colors duration-150 cursor-grab active:cursor-grabbing ${isDragging ? 'bg-slate-500' : 'bg-slate-400 hover:bg-slate-500'}`}
            style={{
              height: `${thumbHeight}px`,
              top: `${thumbTop}px`
            }}
          />
        </div>

        {activeTooltip && (
          <div
            className="absolute bg-gray-900 border border-gray-800 text-white rounded px-2.5 py-1.5 text-[10px] font-black uppercase tracking-widest shadow-xl pointer-events-none transition-all duration-75 z-50 flex items-center gap-1.5"
            style={{ left: `${activeTooltip.x}px`, top: `${activeTooltip.y}px` }}
          >
            <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
            {activeTooltip.text}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between text-[9px] text-gray-400 font-black uppercase tracking-widest border-t border-gray-100 pt-3">
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 bg-slate-700 rounded" />
          <span>Source Transmitter (Src IP)</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 bg-slate-700 rounded" />
          <span>Destination Target (Dst IP)</span>
        </div>
      </div>
    </div>
  );
}