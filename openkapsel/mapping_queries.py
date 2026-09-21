"""Coarse file queries at virtual mapping boundaries, without native mounts."""

from pathlib import Path

from .errors import ApiError


class MappingQueryMixin:
    def _mapping_root(self, path):
        manager = getattr(self.server, "mappings", None)
        row = manager.at_path(path) if manager is not None else None
        return row if row and manager.mount_path(row) == path else None

    @staticmethod
    def _unavailable_mapping(row, path, error):
        return {"name": path.name, "path": str(path), "type": "directory",
                "is_mapping": True, "mapping_id": row["id"], "unavailable": True,
                "error": {"code": error.code, "message": error.message}}

    def _mapping_tree(self, row, path, depth, state):
        remaining = self.server.config.max_tree_nodes - state["count"]
        limits = {"max_tree_nodes": remaining}
        try:
            if state.get("manifest"):
                _, result = self._call_mapping_file_api(row, "fs_manifest", min_version=2,
                    body={"path": ".", "recursive": True, "depth": depth,
                          "include_sha256": state.get("include_sha256", False)},
                    limits_override=limits)
                items = result.get("items")
                if not isinstance(items, list) or not 1 <= len(items) <= remaining:
                    raise ApiError(502, "invalid_mapping_response", "invalid mapping manifest")
                by_path = {}
                for item in items:
                    if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                        raise ApiError(502, "invalid_mapping_response", "invalid mapping manifest item")
                    node = dict(item)
                    current = Path(node["path"])
                    if current in by_path or (current != path and path not in current.parents):
                        raise ApiError(502, "invalid_mapping_response", "invalid mapping manifest path")
                    if current != path:
                        parent = by_path.get(current.parent)
                        if parent is None:
                            raise ApiError(502, "invalid_mapping_response", "invalid mapping manifest order")
                        parent.setdefault("children", []).append(node)
                    by_path[current] = node
                tree, count = by_path.get(path), len(items)
            else:
                _, result = self._call_mapping_file_api(row, "fs_tree",
                    query={"path": ["."], "depth": [str(depth)]}, limits_override=limits)
                tree, count = result.get("tree"), result.get("node_count")
            if not isinstance(tree, dict) or type(count) is not int or not 1 <= count <= remaining:
                raise ApiError(502, "invalid_mapping_response", "invalid mapping tree")
            tree.update(name=path.name, path=str(path), is_mapping=True, mapping_id=row["id"])
            state["count"] += count
            state["truncated"] |= bool(result.get("truncated"))
            return tree
        except ApiError as exc:
            state["count"] += 1
            return self._unavailable_mapping(row, path, exc)

    def _mapping_search(self, row, path, root, query, depth, remaining, includes, excludes):
        forwarded = {key: list(value) for key, value in query.items()}
        forwarded.update(path=["."], depth=[str(depth)], max_results=[str(remaining)])
        # Slash-free globs are basename filters and need no translation. Other
        # globs must be evaluated against the original request root, even when
        # a wildcard spans the mapping boundary or excludes an entire subtree.
        prefix = path.relative_to(root).as_posix() if any("/" in p for p in (*includes, *excludes)) else None
        _, result = self._call_mapping_file_api(row, "fs_search", query=forwarded,
                                                min_version=2, search_prefix=prefix)
        matches = result.get("matches")
        if not isinstance(matches, list) or len(matches) > remaining:
            raise ApiError(502, "invalid_mapping_response", "invalid mapping search results")
        for field in ("files_searched", "skipped_binary", "skipped_large"):
            if type(result.get(field)) is not int or result[field] < 0:
                raise ApiError(502, "invalid_mapping_response", "invalid mapping search counters")
        return result
