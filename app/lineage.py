"""敏感字段血缘核查（纯函数，不依赖 Web 框架与数据库）。

用途
----
开放报表列之前，核查敏感源字段是否沿现有任务依赖「未经脱敏」传到目标表。

输入
----
- 敏感源字段清单 CSV（UTF-8，≤ 256 KiB），表头: 任务,字段
- 字段映射 CSV（UTF-8，≤ 256 KiB），表头: 下游任务,下游字段,上游任务,上游字段,直传/脱敏
  · 每行映射的（下游任务 ← 上游任务）必须对应库中已有的直接依赖
  · 方式列取值：直传 / 脱敏（兼容 direct / masked，大小写不敏感）

判定语义（逐列独立核查，一列的问题不影响其他列）
--------------------------------------------
从（目标任务, 待核查列）出发，沿字段映射向上追溯全部路径：
- 途经边全部为「直传」且路径终点命中敏感源字段 → 该列裸露，列出该路径；
- 「脱敏」边只截断所在路径，同列的其他直传路径继续核查，不被遮住；
- 字段所在任务尚有上游依赖、却缺少该字段到部分上游的映射 → 待核实（不可判安全）；
- 映射成环 → 待核实；已发现的裸露路径仍然展示，其余分支与其他列继续核查。

安全上限：单列路径数 / 访问节点数超限 → 该列记待核实并截断，防止异常输入拖垮服务。
"""
from __future__ import annotations

import csv
import io
import re
from collections import defaultdict

MAX_CSV_BYTES = 256 * 1024        # 每份 CSV 上限 256 KiB
MAX_COLUMNS = 200                 # 单次核查列数上限
MAX_COLUMN_NAME = 128             # 列名长度上限
MAX_PATHS_PER_COLUMN = 500        # 单列裸露路径数上限
MAX_VISITS_PER_COLUMN = 20000     # 单列访问节点数上限

SENSITIVE_HEADERS = ["任务", "字段"]
MAPPING_HEADERS = ["下游任务", "下游字段", "上游任务", "上游字段", "直传/脱敏"]

_DIRECT = {"直传", "direct"}
_MASKED = {"脱敏", "masked"}


# ---------- CSV 解析 ----------

def _decode(data: bytes, label: str):
    """校验大小并按 UTF-8（容忍 BOM）解码，返回 (文本, 错误)。"""
    if not isinstance(data, (bytes, bytearray)):
        return None, f"{label} 内容无效"
    if len(data) > MAX_CSV_BYTES:
        return None, (f"{label} 大小 {len(data)} 字节，"
                      f"超过 256 KiB（{MAX_CSV_BYTES} 字节）上限")
    try:
        return bytes(data).decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, f"{label} 不是有效的 UTF-8 文本"


def _parse_rows(text: str, expected_headers: list[str], label: str):
    """解析 CSV 文本，返回 (数据行[(行号, 单元格列表)], 错误列表)。"""
    try:
        rdr = csv.reader(io.StringIO(text))
        all_rows = [r for r in rdr if any(cell.strip() for cell in r)]
    except csv.Error as e:
        return [], [f"{label} CSV 解析失败: {e}"]
    if not all_rows:
        return [], [f"{label} 为空或缺少表头"]
    header = [c.strip() for c in all_rows[0]]
    if header != expected_headers:
        return [], [f"{label} 表头应为「{','.join(expected_headers)}」，"
                    f"实际为「{','.join(header)}」"]
    rows = []
    errors = []
    for i, r in enumerate(all_rows[1:], start=2):
        if len(r) != len(expected_headers):
            errors.append(f"{label} 第{i}行应有 {len(expected_headers)} 列，"
                          f"实际 {len(r)} 列")
            continue
        rows.append((i, [c.strip() for c in r]))
    return rows, errors


def parse_sensitive(data: bytes):
    """解析敏感源字段清单，返回 (敏感字段集合{(任务,字段)}, 错误列表)。"""
    text, err = _decode(data, "敏感源字段清单")
    if err:
        return set(), [err]
    raw, errors = _parse_rows(text, SENSITIVE_HEADERS, "敏感源字段清单")
    sens: set[tuple[str, str]] = set()
    for i, (task, field) in raw:
        if not task or not field:
            errors.append(f"敏感源字段清单 第{i}行 任务/字段不能为空")
            continue
        sens.add((task, field))
    return sens, errors


def parse_mappings(data: bytes):
    """解析字段映射，返回 (映射列表, 错误列表)。完全重复的行去重。"""
    text, err = _decode(data, "字段映射")
    if err:
        return [], [err]
    raw, errors = _parse_rows(text, MAPPING_HEADERS, "字段映射")
    maps: list[dict] = []
    seen: dict[tuple, str] = {}
    for i, (dt, df, ut, uf, mode_raw) in raw:
        if not all([dt, df, ut, uf, mode_raw]):
            errors.append(f"字段映射 第{i}行 存在空单元格")
            continue
        low = mode_raw.lower()
        if mode_raw in _DIRECT or low in _DIRECT:
            mode = "direct"
        elif mode_raw in _MASKED or low in _MASKED:
            mode = "masked"
        else:
            errors.append(f"字段映射 第{i}行 方式应为 直传/脱敏，"
                          f"实际为「{mode_raw}」")
            continue
        key = (dt, df, ut, uf)
        if key in seen:
            if seen[key] != mode:
                errors.append(
                    f"字段映射 第{i}行 与之前行冲突：同一映射"
                    f"（{dt}.{df}←{ut}.{uf}）既标直传又标脱敏")
            continue
        seen[key] = mode
        maps.append({"line": i, "down_task": dt, "down_field": df,
                     "up_task": ut, "up_field": uf, "mode": mode})
    return maps, errors


# ---------- 列名 ----------

def _split_columns(raw: str):
    cols, seen = [], set()
    for c in re.split(r"[,，\s]+", raw or ""):
        c = c.strip()
        if c and c not in seen:
            seen.add(c)
            cols.append(c)
    return cols


# ---------- 追溯 ----------

def _trace_column(start: tuple[str, str], edges_of: dict, ups_of_task: dict,
                  sens: set) -> dict:
    """追溯单列，返回该列核查结果。"""
    column = start[1]
    exposed: list[list[dict]] = []
    pending: list[dict] = []
    masked_edges = 0
    truncated = False
    visits = 0
    # 栈元素: (节点, 路径, 路径上的节点集合) —— 路径首元素为目标列，mode 为 None
    stack = [(start, [{"task": start[0], "field": start[1], "mode": None}],
              {start})]
    while stack:
        node, path, in_path = stack.pop()
        visits += 1
        if visits > MAX_VISITS_PER_COLUMN or len(exposed) >= MAX_PATHS_PER_COLUMN:
            truncated = True
            break
        task, field = node
        # 途经边全为直传（脱敏边不会把节点压栈），命中敏感源即裸露
        if node != start and node in sens:
            exposed.append(path)
        edges = edges_of.get(node, [])
        # 任务尚有上游依赖、却缺少该字段到部分上游的映射 -> 待核实
        covered = {m["up_task"] for m in edges}
        missing = sorted(ups_of_task.get(task, set()) - covered)
        if missing:
            pending.append({
                "type": "unmapped",
                "detail": (f"任务 {task} 尚有上游依赖未提供字段「{field}」"
                           f"的映射: {', '.join(missing)}"),
                "path": path,
            })
        for m in edges:
            nxt = (m["up_task"], m["up_field"])
            if m["mode"] == "masked":
                masked_edges += 1   # 脱敏只截断所在路径
                continue
            step = {"task": nxt[0], "field": nxt[1], "mode": "直传"}
            if nxt in in_path:
                chain = [f"{s['task']}.{s['field']}" for s in path]
                chain.append(f"{nxt[0]}.{nxt[1]}")
                pending.append({
                    "type": "cycle",
                    "detail": "映射成环: " + " → ".join(chain),
                    "path": path + [step],
                })
                continue
            stack.append((nxt, path + [step], in_path | {nxt}))
    if truncated:
        pending.append({
            "type": "limit",
            "detail": (f"超过安全上限（{MAX_PATHS_PER_COLUMN} 条裸露路径或 "
                       f"{MAX_VISITS_PER_COLUMN} 个节点），结果可能不完整"),
            "path": [],
        })
    status = "exposed" if exposed else ("pending" if pending else "safe")
    return {"column": column, "status": status,
            "exposed_paths": exposed, "pending": pending,
            "masked_edges": masked_edges}


# ---------- 入口 ----------

def check_lineage(tasks: list[dict], deps: list[dict],
                  sensitive_bytes: bytes, mapping_bytes: bytes,
                  target_task_id: int, columns_raw: str) -> dict:
    """核查入口。tasks 需含 id/name；deps 需含 downstream_name/upstream_name。

    返回 {"ok": False, "errors": [...]} 表示输入不合法；
    否则返回 {"ok": True, "target", "columns", "summary", "warnings", "counts"}。
    """
    errors: list[str] = []
    task_by_id = {t["id"]: t for t in tasks}
    task_names = {t["name"] for t in tasks}
    dep_pairs = {(d["downstream_name"], d["upstream_name"]) for d in deps}

    sens, errs = parse_sensitive(sensitive_bytes)
    errors += errs
    maps, errs = parse_mappings(mapping_bytes)
    errors += errs

    # 映射必须对应已有直接依赖
    for m in maps:
        if (m["down_task"], m["up_task"]) not in dep_pairs:
            errors.append(
                f"字段映射 第{m['line']}行 （{m['down_task']} ← {m['up_task']}）"
                f"不对应已有直接依赖（或任务不存在）")

    target = task_by_id.get(target_task_id)
    if target is None:
        errors.append(f"目标任务不存在: id={target_task_id}")

    columns = _split_columns(columns_raw)
    if not columns:
        errors.append("请填写至少一个待核查列")
    elif len(columns) > MAX_COLUMNS:
        errors.append(f"待核查列数量 {len(columns)} 超过上限 {MAX_COLUMNS}")
    elif any(len(c) > MAX_COLUMN_NAME for c in columns):
        errors.append(f"存在长度超过 {MAX_COLUMN_NAME} 的列名")

    if errors:
        return {"ok": False, "errors": errors}

    # 非致命告警：敏感源清单引用了不存在的任务（永不命中，疑似笔误）
    warnings = []
    unknown = sorted({t for (t, _f) in sens} - task_names)
    if unknown:
        warnings.append("敏感源字段清单中的任务不存在（永不命中，请确认是否笔误）: "
                        + ", ".join(unknown))

    edges_of: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for m in maps:
        edges_of[(m["down_task"], m["down_field"])].append(m)
    ups_of_task: dict[str, set[str]] = defaultdict(set)
    for d in deps:
        ups_of_task[d["downstream_name"]].add(d["upstream_name"])

    target_name = target["name"]
    results = [_trace_column((target_name, c), edges_of, ups_of_task, sens)
               for c in columns]
    summary = {
        "exposed": sum(1 for c in results if c["status"] == "exposed"),
        "pending": sum(1 for c in results if c["status"] == "pending"),
        "safe": sum(1 for c in results if c["status"] == "safe"),
    }
    return {
        "ok": True,
        "target": {"id": target_task_id, "name": target_name},
        "columns": results,
        "summary": summary,
        "warnings": warnings,
        "counts": {"sensitive": len(sens), "mappings": len(maps)},
    }
