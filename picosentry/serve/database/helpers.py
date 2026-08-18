from typing import Any


def build_filtered_query(
    table: str,
    org_id: str | int,
    filters: dict[str, Any],
    limit: int,
    order_by: str = "created_at DESC",
    offset: int = 0,
) -> tuple[str, tuple[Any, ...]]:
    query = f"SELECT * FROM {table} WHERE org_id = ?"
    params: list[Any] = [org_id]
    for column, value in filters.items():
        if value is not None:
            query += f" AND {column} = ?"
            params.append(value)
    query += f" ORDER BY {order_by} LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return query, tuple(params)
