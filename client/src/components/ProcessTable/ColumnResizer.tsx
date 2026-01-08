import { useState, useCallback, useEffect, useRef } from 'react';
import clsx from 'clsx';

interface ColumnResizerProps {
  columnId: string;
  currentWidth: number;
  onResize: (columnId: string, newWidth: number) => void;
  minWidth: number;
  maxWidth: number;
}

export function ColumnResizer({
  columnId,
  currentWidth,
  onResize,
  minWidth,
  maxWidth,
}: ColumnResizerProps) {
  const [isResizing, setIsResizing] = useState(false);
  const startXRef = useRef(0);
  const startWidthRef = useRef(0);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsResizing(true);
      startXRef.current = e.clientX;
      startWidthRef.current = currentWidth;
    },
    [currentWidth]
  );

  const handleMouseMove = useCallback(
    (e: MouseEvent) => {
      if (!isResizing) return;

      const delta = e.clientX - startXRef.current;
      const newWidth = Math.min(Math.max(startWidthRef.current + delta, minWidth), maxWidth);
      onResize(columnId, newWidth);
    },
    [isResizing, columnId, onResize, minWidth, maxWidth]
  );

  const handleMouseUp = useCallback(() => {
    setIsResizing(false);
  }, []);

  // Handle double-click to reset to default
  const handleDoubleClick = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      // Reset to midpoint between min and max
      const midWidth = Math.round((minWidth + Math.min(maxWidth, 300)) / 2);
      onResize(columnId, midWidth);
    },
    [columnId, onResize, minWidth, maxWidth]
  );

  // Global mouse event listeners for drag
  useEffect(() => {
    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isResizing, handleMouseMove, handleMouseUp]);

  return (
    <div
      className={clsx(
        'column-resizer',
        isResizing && 'is-resizing'
      )}
      onMouseDown={handleMouseDown}
      onDoubleClick={handleDoubleClick}
      role="separator"
      aria-orientation="vertical"
      aria-valuenow={currentWidth}
      aria-valuemin={minWidth}
      aria-valuemax={maxWidth}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'ArrowLeft') {
          e.preventDefault();
          onResize(columnId, Math.max(currentWidth - 10, minWidth));
        } else if (e.key === 'ArrowRight') {
          e.preventDefault();
          onResize(columnId, Math.min(currentWidth + 10, maxWidth));
        }
      }}
    />
  );
}
