import { useState, useCallback, useEffect, useRef } from 'react';
import {
  STORAGE_KEY,
  getDefaultWidths,
  getColumnConfig,
  generateGridTemplate,
} from '../config/tableColumns';

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function loadFromLocalStorage(): Record<string, number> {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      if (typeof parsed === 'object' && parsed !== null) {
        return { ...getDefaultWidths(), ...parsed };
      }
    }
  } catch {
    // Ignore parse errors
  }
  return getDefaultWidths();
}

function saveToLocalStorage(widths: Record<string, number>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(widths));
  } catch {
    // Ignore storage errors (quota exceeded, etc.)
  }
}

export function useColumnWidths() {
  const [widths, setWidths] = useState<Record<string, number>>(loadFromLocalStorage);
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Debounced save to localStorage
  useEffect(() => {
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }
    saveTimeoutRef.current = setTimeout(() => {
      saveToLocalStorage(widths);
    }, 300);

    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, [widths]);

  const setColumnWidth = useCallback((columnId: string, width: number) => {
    const config = getColumnConfig(columnId);
    if (!config || !config.canResize) return;

    const clampedWidth = clamp(width, config.minWidth, config.maxWidth);
    setWidths((prev) => ({
      ...prev,
      [columnId]: clampedWidth,
    }));
  }, []);

  const resetWidths = useCallback(() => {
    const defaults = getDefaultWidths();
    setWidths(defaults);
    saveToLocalStorage(defaults);
  }, []);

  const gridTemplate = generateGridTemplate(widths);

  return {
    widths,
    setColumnWidth,
    resetWidths,
    gridTemplate,
  };
}
