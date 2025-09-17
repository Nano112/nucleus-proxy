"""
Search and query engine for M5 milestone.

Provides advanced search capabilities over the indexed file metadata,
including full-text search, filtering, and sorting functionality.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from app.db.sqlite import Database, FileEntry, FileType, IndexStatus, get_database

logger = logging.getLogger(__name__)


class SortOrder(str, Enum):
    """Sort order options"""
    ASC = "asc"
    DESC = "desc"


class SortField(str, Enum):
    """Sortable fields"""
    NAME = "name"
    SIZE = "size" 
    MODIFIED = "modified_at"
    CREATED_BY = "created_by"
    PATH = "path"
    TYPE = "type"


@dataclass
class SearchFilter:
    """Search filter configuration"""
    file_types: Optional[List[FileType]] = None
    size_min: Optional[int] = None
    size_max: Optional[int] = None
    modified_since: Optional[datetime] = None
    modified_until: Optional[datetime] = None
    created_by: Optional[str] = None
    parent_path: Optional[str] = None
    has_tags: Optional[List[str]] = None
    content_types: Optional[List[str]] = None


@dataclass
class SearchSort:
    """Search sort configuration"""
    field: SortField = SortField.NAME
    order: SortOrder = SortOrder.ASC


@dataclass
class SearchResult:
    """Search result with metadata"""
    files: List[FileEntry]
    total_count: int
    page: int
    page_size: int
    has_more: bool
    query_time_ms: float
    filters_applied: Dict[str, Any]


class SearchEngine:
    """
    Advanced search engine for file metadata.
    
    Provides full-text search, filtering, and sorting capabilities
    over the indexed file database.
    """
    
    def __init__(self, database: Optional[Database] = None):
        self.database = database
    
    async def initialize(self):
        """Initialize the search engine"""
        if not self.database:
            self.database = await get_database()
    
    async def search(self,
                    query: Optional[str] = None,
                    filters: Optional[SearchFilter] = None,
                    sort: Optional[SearchSort] = None,
                    page: int = 1,
                    page_size: int = 50) -> SearchResult:
        """
        Perform advanced search over indexed files.
        
        Args:
            query: Full-text search query (optional)
            filters: Search filters to apply
            sort: Sort configuration
            page: Page number (1-based)
            page_size: Number of results per page
            
        Returns:
            SearchResult with files and metadata
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # Build the search query
            sql_parts = self._build_search_query(query, filters, sort)
            
            # Execute the query with pagination
            offset = (page - 1) * page_size
            files = await self._execute_search_query(
                sql_parts['query'], 
                sql_parts['params'], 
                page_size, 
                offset
            )
            
            # Get total count for pagination
            total_count = await self._get_search_count(
                sql_parts['count_query'], 
                sql_parts['count_params']
            )
            
            # Calculate metadata
            query_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            has_more = (offset + len(files)) < total_count
            
            return SearchResult(
                files=files,
                total_count=total_count,
                page=page,
                page_size=page_size,
                has_more=has_more,
                query_time_ms=query_time,
                filters_applied=self._serialize_filters(filters)
            )
            
        except Exception as e:
            logger.error(f"Error during search: {e}")
            # Return empty result on error
            return SearchResult(
                files=[],
                total_count=0,
                page=page,
                page_size=page_size,
                has_more=False,
                query_time_ms=0,
                filters_applied={}
            )
    
    async def suggest_completions(self, partial_query: str, limit: int = 10) -> List[str]:
        """
        Suggest search completions based on partial query.
        
        Args:
            partial_query: Partial search term
            limit: Maximum number of suggestions
            
        Returns:
            List of suggested completions
        """
        try:
            import aiosqlite
            
            suggestions = []
            async with aiosqlite.connect(self.database.db_path) as db:
                # Search for matching file names
                async with db.execute("""
                    SELECT DISTINCT name FROM file_entries 
                    WHERE name LIKE ? AND index_status = 'indexed'
                    ORDER BY name LIMIT ?
                """, (f"{partial_query}%", limit)) as cursor:
                    rows = await cursor.fetchall()
                    suggestions.extend([row[0] for row in rows])
                
                # Search for matching paths
                if len(suggestions) < limit:
                    remaining = limit - len(suggestions)
                    async with db.execute("""
                        SELECT DISTINCT path FROM file_entries 
                        WHERE path LIKE ? AND index_status = 'indexed'
                        AND path NOT IN (SELECT path FROM file_entries WHERE name LIKE ?)
                        ORDER BY path LIMIT ?
                    """, (f"%{partial_query}%", f"{partial_query}%", remaining)) as cursor:
                        rows = await cursor.fetchall()
                        suggestions.extend([row[0] for row in rows])
            
            return suggestions[:limit]
            
        except Exception as e:
            logger.error(f"Error getting search suggestions: {e}")
            return []
    
    async def get_facets(self, query: Optional[str] = None) -> Dict[str, Any]:
        """
        Get search facets (aggregated counts by category).
        
        Args:
            query: Optional search query to filter facets
            
        Returns:
            Dictionary with facet counts
        """
        try:
            import aiosqlite
            
            facets = {}
            
            # Base WHERE clause for query filtering
            where_clause = "WHERE index_status = 'indexed'"
            params = []
            
            if query:
                where_clause += " AND (name MATCH ? OR path MATCH ?)"
                params.extend([query, query])
            
            async with aiosqlite.connect(self.database.db_path) as db:
                # File type facets
                async with db.execute(f"""
                    SELECT type, COUNT(*) as count FROM file_entries 
                    {where_clause} GROUP BY type ORDER BY count DESC
                """, params) as cursor:
                    type_facets = await cursor.fetchall()
                    facets['file_types'] = [{'value': t, 'count': c} for t, c in type_facets]
                
                # Size range facets
                async with db.execute(f"""
                    SELECT 
                        CASE 
                            WHEN size < 1024 THEN 'small'
                            WHEN size < 1048576 THEN 'medium'
                            WHEN size < 104857600 THEN 'large'
                            ELSE 'huge'
                        END as size_range,
                        COUNT(*) as count
                    FROM file_entries 
                    {where_clause} AND size IS NOT NULL
                    GROUP BY size_range ORDER BY count DESC
                """, params) as cursor:
                    size_facets = await cursor.fetchall()
                    facets['size_ranges'] = [{'value': s, 'count': c} for s, c in size_facets]
                
                # Content type facets (top 10)
                async with db.execute(f"""
                    SELECT content_type, COUNT(*) as count FROM file_entries 
                    {where_clause} AND content_type IS NOT NULL
                    GROUP BY content_type ORDER BY count DESC LIMIT 10
                """, params) as cursor:
                    content_facets = await cursor.fetchall()
                    facets['content_types'] = [{'value': ct, 'count': c} for ct, c in content_facets]
                
                # Created by facets (top 10)
                async with db.execute(f"""
                    SELECT created_by, COUNT(*) as count FROM file_entries 
                    {where_clause} AND created_by IS NOT NULL
                    GROUP BY created_by ORDER BY count DESC LIMIT 10
                """, params) as cursor:
                    creator_facets = await cursor.fetchall()
                    facets['creators'] = [{'value': cb, 'count': c} for cb, c in creator_facets]
            
            return facets
            
        except Exception as e:
            logger.error(f"Error getting search facets: {e}")
            return {}
    
    async def get_popular_searches(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get popular search terms (would need search logging to implement fully).
        
        For now, returns sample popular terms based on file content.
        """
        try:
            import aiosqlite
            
            popular = []
            async with aiosqlite.connect(self.database.db_path) as db:
                # Get most common file extensions as popular searches
                async with db.execute("""
                    SELECT 
                        SUBSTR(name, INSTR(name, '.') + 1) as extension,
                        COUNT(*) as count
                    FROM file_entries 
                    WHERE index_status = 'indexed' 
                    AND name LIKE '%.%'
                    GROUP BY extension 
                    ORDER BY count DESC 
                    LIMIT ?
                """, (limit,)) as cursor:
                    rows = await cursor.fetchall()
                    popular = [{'term': ext, 'count': count} for ext, count in rows]
            
            return popular
            
        except Exception as e:
            logger.error(f"Error getting popular searches: {e}")
            return []
    
    def _build_search_query(self, 
                          query: Optional[str], 
                          filters: Optional[SearchFilter], 
                          sort: Optional[SearchSort]) -> Dict[str, Any]:
        """Build SQL query components for search"""
        
        # Base query structure
        base_tables = "FROM file_entries fe"
        base_where = "WHERE fe.index_status = 'indexed'"
        params = []
        count_params = []
        
        # Add FTS join if query provided
        if query:
            base_tables += " JOIN file_search fs ON fe.path = fs.path"
            base_where += " AND fs MATCH ?"
            params.append(query)
            count_params.append(query)
        
        # Apply filters
        if filters:
            filter_clauses, filter_params = self._build_filter_clauses(filters)
            if filter_clauses:
                base_where += " AND " + " AND ".join(filter_clauses)
                params.extend(filter_params)
                count_params.extend(filter_params)
        
        # Build sort clause
        sort_clause = self._build_sort_clause(sort or SearchSort())
        
        # Main query
        main_query = f"""
            SELECT fe.* {base_tables}
            {base_where}
            {sort_clause}
            LIMIT ? OFFSET ?
        """
        
        # Count query
        count_query = f"""
            SELECT COUNT(*) {base_tables}
            {base_where}
        """
        
        return {
            'query': main_query,
            'params': params,
            'count_query': count_query,
            'count_params': count_params
        }
    
    def _build_filter_clauses(self, filters: SearchFilter) -> Tuple[List[str], List[Any]]:
        """Build WHERE clauses for filters"""
        clauses = []
        params = []
        
        if filters.file_types:
            placeholders = ','.join('?' * len(filters.file_types))
            clauses.append(f"fe.type IN ({placeholders})")
            params.extend([ft.value for ft in filters.file_types])
        
        if filters.size_min is not None:
            clauses.append("fe.size >= ?")
            params.append(filters.size_min)
        
        if filters.size_max is not None:
            clauses.append("fe.size <= ?")
            params.append(filters.size_max)
        
        if filters.modified_since:
            clauses.append("datetime(fe.modified_at) >= ?")
            params.append(filters.modified_since.isoformat())
        
        if filters.modified_until:
            clauses.append("datetime(fe.modified_at) <= ?")
            params.append(filters.modified_until.isoformat())
        
        if filters.created_by:
            clauses.append("fe.created_by = ?")
            params.append(filters.created_by)
        
        if filters.parent_path:
            clauses.append("fe.parent = ?")
            params.append(filters.parent_path)
        
        if filters.content_types:
            placeholders = ','.join('?' * len(filters.content_types))
            clauses.append(f"fe.content_type IN ({placeholders})")
            params.extend(filters.content_types)
        
        if filters.has_tags:
            # This would need JSON query capabilities in SQLite
            for tag in filters.has_tags:
                clauses.append("fe.tags LIKE ?")
                params.append(f'%"{tag}"%')
        
        return clauses, params
    
    def _build_sort_clause(self, sort: SearchSort) -> str:
        """Build ORDER BY clause"""
        field_map = {
            SortField.NAME: "fe.name",
            SortField.SIZE: "fe.size",
            SortField.MODIFIED: "fe.modified_at",
            SortField.CREATED_BY: "fe.created_by",
            SortField.PATH: "fe.path",
            SortField.TYPE: "fe.type"
        }
        
        field = field_map.get(sort.field, "fe.name")
        direction = sort.order.value.upper()
        
        return f"ORDER BY {field} {direction}"
    
    async def _execute_search_query(self, 
                                  query: str, 
                                  params: List[Any], 
                                  limit: int, 
                                  offset: int) -> List[FileEntry]:
        """Execute the main search query"""
        try:
            import aiosqlite
            
            # Add pagination parameters
            query_params = params + [limit, offset]
            
            async with aiosqlite.connect(self.database.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, query_params) as cursor:
                    rows = await cursor.fetchall()
                    return [self.database._row_to_file_entry(row) for row in rows]
                    
        except Exception as e:
            logger.error(f"Error executing search query: {e}")
            return []
    
    async def _get_search_count(self, query: str, params: List[Any]) -> int:
        """Get total count for search results"""
        try:
            import aiosqlite
            
            async with aiosqlite.connect(self.database.db_path) as db:
                async with db.execute(query, params) as cursor:
                    result = await cursor.fetchone()
                    return result[0] if result else 0
                    
        except Exception as e:
            logger.error(f"Error getting search count: {e}")
            return 0
    
    def _serialize_filters(self, filters: Optional[SearchFilter]) -> Dict[str, Any]:
        """Serialize filters for result metadata"""
        if not filters:
            return {}
        
        serialized = {}
        if filters.file_types:
            serialized['file_types'] = [ft.value for ft in filters.file_types]
        if filters.size_min is not None:
            serialized['size_min'] = filters.size_min
        if filters.size_max is not None:
            serialized['size_max'] = filters.size_max
        if filters.modified_since:
            serialized['modified_since'] = filters.modified_since.isoformat()
        if filters.modified_until:
            serialized['modified_until'] = filters.modified_until.isoformat()
        if filters.created_by:
            serialized['created_by'] = filters.created_by
        if filters.parent_path:
            serialized['parent_path'] = filters.parent_path
        if filters.has_tags:
            serialized['has_tags'] = filters.has_tags
        if filters.content_types:
            serialized['content_types'] = filters.content_types
        
        return serialized


# Global search engine instance
_search_engine: Optional[SearchEngine] = None


async def get_search_engine() -> SearchEngine:
    """Get or create the global search engine instance"""
    global _search_engine
    if _search_engine is None:
        _search_engine = SearchEngine()
        await _search_engine.initialize()
    return _search_engine


async def initialize_search_engine():
    """Initialize the search engine on startup"""
    await get_search_engine()