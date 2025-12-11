import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { flexRender, getCoreRowModel, useReactTable, getSortedRowModel, getFilteredRowModel, getPaginationRowModel } from '@tanstack/react-table';
import { debounce } from 'lodash';

/**
 * Advanced Smart Table Component
 * Features: Virtual scrolling, sorting, filtering, column resizing, row selection, export
 */
const SmartTable = ({
  data = [],
  columns = [],
  enableSorting = true,
  enableFiltering = true,
  enableSelection = false,
  enableVirtualization = true,
  enableColumnResizing = true,
  enableExport = true,
  pageSize = 50,
  height = 600,
  onRowClick,
  onSelectionChange,
  className = '',
  ...props
}) => {
  const [sorting, setSorting] = useState([]);
  const [columnFilters, setColumnFilters] = useState([]);
  const [globalFilter, setGlobalFilter] = useState('');
  const [rowSelection, setRowSelection] = useState({});
  const [columnVisibility, setColumnVisibility] = useState({});
  const [columnSizing, setColumnSizing] = useState({});

  const tableContainerRef = useRef(null);

  // Enhanced columns with default configurations
  const enhancedColumns = useMemo(() => {
    return columns.map(column => ({
      ...column,
      enableSorting: column.enableSorting ?? enableSorting,
      enableColumnFilter: column.enableColumnFilter ?? enableFiltering,
      enableResizing: column.enableResizing ?? enableColumnResizing,
      size: column.size || 150,
      minSize: column.minSize || 50,
      maxSize: column.maxSize || 500,
      // Add selection column if enabled
      ...(enableSelection && column.id === 'select' ? {
        header: ({ table }) => (
          <input
            type="checkbox"
            checked={table.getIsAllRowsSelected()}
            indeterminate={table.getIsSomeRowsSelected()}
            onChange={table.getToggleAllRowsSelectedHandler()}
            className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
          />
        ),
        cell: ({ row }) => (
          <input
            type="checkbox"
            checked={row.getIsSelected()}
            disabled={!row.getCanSelect()}
            indeterminate={row.getIsSomeSelected()}
            onChange={row.getToggleSelectedHandler()}
            className="rounded border-gray-300 text-cyan-600 focus:ring-cyan-500"
          />
        ),
        enableSorting: false,
        enableColumnFilter: false,
        size: 50,
        minSize: 50,
        maxSize: 50
      } : {})
    }));
  }, [columns, enableSorting, enableFiltering, enableColumnResizing, enableSelection]);

  // Table instance
  const table = useReactTable({
    data,
    columns: enhancedColumns,
    state: {
      sorting,
      columnFilters,
      globalFilter,
      rowSelection,
      columnVisibility,
      columnSizing
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    onRowSelectionChange: setRowSelection,
    onColumnVisibilityChange: setColumnVisibility,
    onColumnSizingChange: setColumnSizing,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    enableRowSelection: enableSelection,
    enableColumnResizing: enableColumnResizing,
    columnResizeMode: 'onChange',
    initialState: {
      pagination: {
        pageSize
      }
    }
  });

  // Virtual scrolling setup
  const { rows } = table.getRowModel();
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 50,
    overscan: 10,
    enabled: enableVirtualization
  });

  // Debounced global filter
  const debouncedGlobalFilter = useMemo(
    () => debounce((value) => setGlobalFilter(value), 300),
    []
  );

  // Handle row selection changes
  useEffect(() => {
    if (onSelectionChange) {
      const selectedRows = table.getSelectedRowModel().rows.map(row => row.original);
      onSelectionChange(selectedRows);
    }
  }, [rowSelection, onSelectionChange, table]);

  // Export functionality
  const exportToCSV = useCallback(() => {
    const headers = table.getVisibleLeafColumns().map(column => column.columnDef.header);
    const csvData = [
      headers.join(','),
      ...rows.map(row => 
        row.getVisibleCells().map(cell => 
          `"${flexRender(cell.column.columnDef.cell, cell.getContext())}"`
        ).join(',')
      )
    ].join('\n');

    const blob = new Blob([csvData], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'table-data.csv';
    a.click();
    URL.revokeObjectURL(url);
  }, [table, rows]);

  // Column visibility toggle
  const ColumnVisibilityDropdown = () => (
    <div className="relative inline-block text-left">
      <details className="dropdown">
        <summary className="btn btn-sm btn-outline">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z" />
          </svg>
          Columns
        </summary>
        <div className="dropdown-content bg-base-100 rounded-box z-[1] w-52 p-2 shadow">
          {table.getAllLeafColumns().map(column => (
            <label key={column.id} className="flex items-center space-x-2 p-1">
              <input
                type="checkbox"
                checked={column.getIsVisible()}
                onChange={column.getToggleVisibilityHandler()}
                className="checkbox checkbox-xs"
              />
              <span className="text-sm">{column.columnDef.header}</span>
            </label>
          ))}
        </div>
      </details>
    </div>
  );

  // Table toolbar
  const TableToolbar = () => (
    <div className="flex items-center justify-between p-4 bg-base-200 rounded-t-lg">
      <div className="flex items-center space-x-4">
        {/* Global search */}
        {enableFiltering && (
          <div className="form-control">
            <input
              type="text"
              placeholder="Search all columns..."
              className="input input-sm input-bordered w-64"
              onChange={(e) => debouncedGlobalFilter(e.target.value)}
            />
          </div>
        )}

        {/* Selection info */}
        {enableSelection && Object.keys(rowSelection).length > 0 && (
          <div className="badge badge-primary">
            {Object.keys(rowSelection).length} selected
          </div>
        )}
      </div>

      <div className="flex items-center space-x-2">
        {/* Column visibility */}
        <ColumnVisibilityDropdown />

        {/* Export button */}
        {enableExport && (
          <button
            onClick={exportToCSV}
            className="btn btn-sm btn-outline"
            title="Export to CSV"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Export
          </button>
        )}

        {/* Refresh button */}
        <button
          onClick={() => window.location.reload()}
          className="btn btn-sm btn-outline"
          title="Refresh data"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>
    </div>
  );

  // Render virtual table
  const renderVirtualTable = () => {
    const virtualItems = virtualizer.getVirtualItems();

    return (
      <div
        ref={tableContainerRef}
        className="overflow-auto"
        style={{ height }}
      >
        <table className="table table-zebra w-full" style={{ width: table.getCenterTotalSize() }}>
          <thead className="sticky top-0 z-10 bg-base-200">
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map(header => (
                  <th
                    key={header.id}
                    className="relative"
                    style={{ width: header.getSize() }}
                  >
                    <div
                      className={`flex items-center space-x-2 ${
                        header.column.getCanSort() ? 'cursor-pointer select-none' : ''
                      }`}
                      onClick={header.column.getToggleSortingHandler()}
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      
                      {/* Sort indicator */}
                      {header.column.getCanSort() && (
                        <span className="text-xs">
                          {{
                            asc: '↑',
                            desc: '↓'
                          }[header.column.getIsSorted()] ?? '↕'}
                        </span>
                      )}
                    </div>

                    {/* Column filter */}
                    {header.column.getCanFilter() && (
                      <div className="mt-1">
                        <input
                          type="text"
                          placeholder={`Filter ${header.column.columnDef.header}...`}
                          className="input input-xs input-bordered w-full"
                          value={header.column.getFilterValue() ?? ''}
                          onChange={(e) => header.column.setFilterValue(e.target.value)}
                        />
                      </div>
                    )}

                    {/* Resize handle */}
                    {header.column.getCanResize() && (
                      <div
                        onMouseDown={header.getResizeHandler()}
                        onTouchStart={header.getResizeHandler()}
                        className="absolute right-0 top-0 h-full w-1 bg-gray-300 cursor-col-resize hover:bg-cyan-500 opacity-0 hover:opacity-100"
                      />
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </thead>

          <tbody>
            <tr style={{ height: virtualizer.getTotalSize() }}>
              <td colSpan={table.getVisibleLeafColumns().length} />
            </tr>
            {virtualItems.map(virtualRow => {
              const row = rows[virtualRow.index];
              return (
                <tr
                  key={row.id}
                  className={`hover:bg-base-300 ${
                    row.getIsSelected() ? 'bg-cyan-50' : ''
                  } ${onRowClick ? 'cursor-pointer' : ''}`}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: `${virtualRow.size}px`,
                    transform: `translateY(${virtualRow.start}px)`
                  }}
                  onClick={() => onRowClick?.(row.original)}
                >
                  {row.getVisibleCells().map(cell => (
                    <td
                      key={cell.id}
                      style={{ width: cell.column.getSize() }}
                      className="truncate"
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  };

  // Render regular table
  const renderRegularTable = () => (
    <div className="overflow-auto" style={{ height }}>
      <table className="table table-zebra w-full">
        <thead className="sticky top-0 z-10 bg-base-200">
          {table.getHeaderGroups().map(headerGroup => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map(header => (
                <th key={header.id} style={{ width: header.getSize() }}>
                  <div
                    className={`flex items-center space-x-2 ${
                      header.column.getCanSort() ? 'cursor-pointer select-none' : ''
                    }`}
                    onClick={header.column.getToggleSortingHandler()}
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {header.column.getCanSort() && (
                      <span className="text-xs">
                        {{
                          asc: '↑',
                          desc: '↓'
                        }[header.column.getIsSorted()] ?? '↕'}
                      </span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map(row => (
            <tr
              key={row.id}
              className={`hover:bg-base-300 ${
                row.getIsSelected() ? 'bg-cyan-50' : ''
              } ${onRowClick ? 'cursor-pointer' : ''}`}
              onClick={() => onRowClick?.(row.original)}
            >
              {row.getVisibleCells().map(cell => (
                <td key={cell.id} className="truncate">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  // Pagination
  const TablePagination = () => (
    <div className="flex items-center justify-between p-4 bg-base-200 rounded-b-lg">
      <div className="flex items-center space-x-2">
        <span className="text-sm">
          Showing {table.getState().pagination.pageIndex * table.getState().pagination.pageSize + 1} to{' '}
          {Math.min(
            (table.getState().pagination.pageIndex + 1) * table.getState().pagination.pageSize,
            table.getFilteredRowModel().rows.length
          )}{' '}
          of {table.getFilteredRowModel().rows.length} results
        </span>
      </div>

      <div className="flex items-center space-x-2">
        <button
          onClick={() => table.setPageIndex(0)}
          disabled={!table.getCanPreviousPage()}
          className="btn btn-sm btn-outline"
        >
          {'<<'}
        </button>
        <button
          onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
          className="btn btn-sm btn-outline"
        >
          {'<'}
        </button>
        <span className="text-sm">
          Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
        </span>
        <button
          onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
          className="btn btn-sm btn-outline"
        >
          {'>'}
        </button>
        <button
          onClick={() => table.setPageIndex(table.getPageCount() - 1)}
          disabled={!table.getCanNextPage()}
          className="btn btn-sm btn-outline"
        >
          {'>>'}
        </button>
      </div>
    </div>
  );

  return (
    <div className={`smart-table ${className}`} {...props}>
      <TableToolbar />
      {enableVirtualization ? renderVirtualTable() : renderRegularTable()}
      <TablePagination />
    </div>
  );
};

export default React.memo(SmartTable);
