export interface ColumnConfig {
  id: string;
  header: string;
  minWidth: number;
  maxWidth: number;
  defaultWidth: number;
  canResize: boolean;
  truncate: boolean;
  flex?: number;
}

export const COLUMN_CONFIGS: ColumnConfig[] = [
  {
    id: 'level',
    header: 'Risk',
    minWidth: 70,
    maxWidth: 120,
    defaultWidth: 80,
    canResize: true,
    truncate: false,
  },
  {
    id: 'pid',
    header: 'PID',
    minWidth: 60,
    maxWidth: 100,
    defaultWidth: 70,
    canResize: true,
    truncate: false,
  },
  {
    id: 'name',
    header: 'Process',
    minWidth: 120,
    maxWidth: 400,
    defaultWidth: 180,
    canResize: true,
    truncate: true,
  },
  {
    id: 'user',
    header: 'User',
    minWidth: 60,
    maxWidth: 150,
    defaultWidth: 90,
    canResize: true,
    truncate: true,
  },
  {
    id: 'cpu',
    header: 'CPU %',
    minWidth: 60,
    maxWidth: 100,
    defaultWidth: 70,
    canResize: true,
    truncate: false,
  },
  {
    id: 'mem',
    header: 'Mem %',
    minWidth: 60,
    maxWidth: 100,
    defaultWidth: 70,
    canResize: true,
    truncate: false,
  },
  {
    id: 'connections',
    header: 'Network',
    minWidth: 100,
    maxWidth: 180,
    defaultWidth: 130,
    canResize: true,
    truncate: false,
  },
  {
    id: 'reasons',
    header: 'Indicators',
    minWidth: 150,
    maxWidth: Infinity,
    defaultWidth: 200,
    canResize: false,
    truncate: false,
    flex: 1,
  },
];

export const STORAGE_KEY = 'procscope-column-widths';

export function getDefaultWidths(): Record<string, number> {
  return COLUMN_CONFIGS.reduce(
    (acc, col) => {
      acc[col.id] = col.defaultWidth;
      return acc;
    },
    {} as Record<string, number>
  );
}

export function getColumnConfig(id: string): ColumnConfig | undefined {
  return COLUMN_CONFIGS.find((col) => col.id === id);
}

export function generateGridTemplate(widths: Record<string, number>): string {
  return COLUMN_CONFIGS.map((col) =>
    col.flex ? '1fr' : `${widths[col.id] || col.defaultWidth}px`
  ).join(' ');
}
