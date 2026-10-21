import { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';

const useSortedData = (data, defaultSortConfig = { key: null, direction: 'asc' }) => {
  const [sortConfig, setSortConfig] = useState(defaultSortConfig);

  const sortedData = useMemo(() => {
    if (!data) return [];

    let sortableItems = [...data];
    if (sortConfig.key !== null) {
      sortableItems.sort((a, b) => {
        // Handle nested properties (e.g., 'zone.name')
        const getValue = (obj, path) => {
          return path.split('.').reduce((acc, part) => acc && acc[part], obj);
        };

        const aValue = getValue(a, sortConfig.key);
        const bValue = getValue(b, sortConfig.key);

        // Missing values always sort last, regardless of direction
        if (aValue === null || aValue === undefined) return 1;
        if (bValue === null || bValue === undefined) return -1;

        let cmp;
        if (typeof aValue === 'string' && typeof bValue === 'string') {
          // Case-insensitive with numeric awareness so "host10" sorts after
          // "host2" and "API.example.com" groups with "api.example.com"
          cmp = aValue.localeCompare(bValue, undefined, { numeric: true, sensitivity: 'base' });
        } else {
          cmp = aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
        }
        return sortConfig.direction === 'asc' ? cmp : -cmp;
      });
    }
    return sortableItems;
  }, [data, sortConfig]);

  const requestSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const getSortIndicator = (name) => {
    const style = { width: 11, height: 11, marginLeft: 4, verticalAlign: 'middle' };
    if (sortConfig.key !== name) {
      return <ChevronsUpDown style={{ ...style, opacity: 0.4 }} />;
    }
    return sortConfig.direction === 'asc' ? <ChevronUp style={style} /> : <ChevronDown style={style} />;
  };

  return { items: sortedData, requestSort, sortConfig, getSortIndicator };
};

export default useSortedData;
