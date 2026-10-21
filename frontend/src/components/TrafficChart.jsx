import React from 'react';
import { Activity } from 'lucide-react';
import {
  ResponsiveContainer, ComposedChart, Area, Line, XAxis, YAxis,
  Tooltip, CartesianGrid, Legend
} from 'recharts';
import { formatBytes, formatCompact, formatNumber, parseUTC } from '../utils/helpers';

// Token values from skylar.css; recharts cannot read CSS variables.
export const CHART = {
  requests: '#E56A1F' /* --brand-orange: headline series */,
  bandwidth: '#2496ED' /* --brand-blue */,
  cached: '#5FA3C7' /* --status-low */,
  threats: '#E24B4A' /* --status-critical */,
  grid: '#2A3240' /* --border-subtle */,
  axis: '#6B7280' /* --text-tertiary */,
  tooltipBg: '#1C222D' /* --bg-card */,
  tooltipBorder: '#3A4556' /* --border-emphasis */,
  text: '#E8ECF2' /* --text-primary */,
};

export const CHART_TOOLTIP_STYLE = {
  background: CHART.tooltipBg,
  border: `1px solid ${CHART.tooltipBorder}`,
  borderRadius: 4,
  fontSize: 12,
};

export const CHART_TICK = { fontSize: 11, fill: CHART.axis };

// Hourly traffic buckets rendered as a dual-axis time series:
// requests as an area and cached/threats as lines (left axis), bandwidth as a line (right axis).
// Expects data ascending by timestamp: [{ timestamp, requests, cached, bandwidth, threats }]
const TrafficChart = ({ data, height = 320, title = 'Traffic over time' }) => {
  if (!data || data.length === 0) return null;

  const spansDays = data.length > 26;
  const formatTick = (ts) => {
    const d = parseUTC(ts);
    if (!d) return '';
    return spansDays
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  };

  const formatLabel = (ts) => {
    const d = parseUTC(ts);
    return d ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title"><Activity className="card-title-icon" />{title}<span className="card-subtitle">hourly buckets</span></h2>
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data}>
          <CartesianGrid stroke={CHART.grid} vertical={false} />
          <XAxis dataKey="timestamp" tickFormatter={formatTick} tick={CHART_TICK} axisLine={{ stroke: CHART.grid }} tickLine={false} minTickGap={30} />
          <YAxis yAxisId="requests" tickFormatter={formatCompact} tick={CHART_TICK} axisLine={false} tickLine={false} width={44} />
          <YAxis yAxisId="bandwidth" orientation="right" tickFormatter={(v) => formatBytes(v, 0)} tick={CHART_TICK} axisLine={false} tickLine={false} width={64} />
          <Tooltip
            labelFormatter={formatLabel}
            formatter={(value, name) => (name === 'Bandwidth' ? formatBytes(value) : formatNumber(value))}
            contentStyle={CHART_TOOLTIP_STYLE}
            labelStyle={{ color: CHART.text }}
            cursor={{ stroke: CHART.axis }}
          />
          <Legend wrapperStyle={{ fontSize: 11 }} iconSize={10} />
          <Area yAxisId="requests" type="monotone" dataKey="requests" name="Requests" stroke={CHART.requests} fill={CHART.requests} fillOpacity={0.12} strokeWidth={2} dot={false} />
          <Line yAxisId="requests" type="monotone" dataKey="cached" name="Cached" stroke={CHART.cached} strokeWidth={1.5} dot={false} />
          <Line yAxisId="bandwidth" type="monotone" dataKey="bandwidth" name="Bandwidth" stroke={CHART.bandwidth} strokeWidth={1.5} dot={false} />
          <Line yAxisId="requests" type="monotone" dataKey="threats" name="Threats" stroke={CHART.threats} strokeWidth={1.5} dot={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TrafficChart;
