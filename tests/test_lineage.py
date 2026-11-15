"""敏感字段血缘核查单元测试：python -m unittest discover tests -v"""
import unittest

from app.lineage import MAX_CSV_BYTES, check_lineage


def T(tid, name):
    return {"id": tid, "name": name}


def D(down, up):
    return {"downstream_name": down, "upstream_name": up}


def make_csv(header, rows):
    lines = [",".join(header)] + [",".join(map(str, r)) for r in rows]
    return "\n".join(lines).encode("utf-8")


def sens_csv(*pairs):
    return make_csv(["任务", "字段"], [list(p) for p in pairs])


def map_csv(*rows):
    # rows: (下游任务, 下游字段, 上游任务, 上游字段, 方式)
    return make_csv(["下游任务", "下游字段", "上游任务", "上游字段", "直传/脱敏"],
                    [list(r) for r in rows])


class TestTrace(unittest.TestCase):
    def setUp(self):
        # T <- A <- S ; T <- B <- S （菱形）
        self.tasks = [T(1, "T"), T(2, "A"), T(3, "B"), T(4, "S")]
        self.deps = [D("T", "A"), D("T", "B"), D("A", "S"), D("B", "S")]

    def check(self, sens, maps, columns="c", target=1, tasks=None, deps=None):
        return check_lineage(tasks or self.tasks, deps or self.deps,
                             sens, maps, target, columns)

    def col(self, result, name="c"):
        self.assertTrue(result["ok"], result.get("errors"))
        return next(c for c in result["columns"] if c["column"] == name)

    def test_exposed_all_direct_chain(self):
        r = self.check(sens_csv(("S", "g")),
                       map_csv(("T", "c", "A", "f", "直传"),
                               ("A", "f", "S", "g", "直传")))
        c = self.col(r)
        self.assertEqual(c["status"], "exposed")
        self.assertEqual(len(c["exposed_paths"]), 1)
        path = c["exposed_paths"][0]
        self.assertEqual([(s["task"], s["field"]) for s in path],
                         [("T", "c"), ("A", "f"), ("S", "g")])

    def test_masked_truncates_only_its_own_path(self):
        # 菱形：A 分支脱敏、B 分支直传 —— 脱敏不能遮住 B 的直传路径
        r = self.check(sens_csv(("S", "g")),
                       map_csv(("T", "c", "A", "f", "直传"),
                               ("T", "c", "B", "f", "直传"),
                               ("A", "f", "S", "g", "脱敏"),
                               ("B", "f", "S", "g", "直传")))
        c = self.col(r)
        self.assertEqual(c["status"], "exposed")
        self.assertEqual(len(c["exposed_paths"]), 1)
        path = c["exposed_paths"][0]
        self.assertEqual([(s["task"], s["field"]) for s in path],
                         [("T", "c"), ("B", "f"), ("S", "g")])
        self.assertEqual(c["masked_edges"], 1)

    def test_masked_only_path_is_safe(self):
        r = self.check(sens_csv(("S", "g")),
                       map_csv(("T", "c", "A", "f", "脱敏"),
                               ("A", "f", "S", "g", "直传")),
                       tasks=[T(1, "T"), T(2, "A"), T(4, "S")],
                       deps=[D("T", "A"), D("A", "S")])
        c = self.col(r)
        self.assertEqual(c["status"], "safe")
        self.assertEqual(c["masked_edges"], 1)
        self.assertEqual(c["exposed_paths"], [])

    def test_unmapped_upstream_is_pending(self):
        # T 依赖 A、B，但字段 c 只映射到 A
        r = self.check(sens_csv(),
                       map_csv(("T", "c", "A", "f", "直传")),
                       tasks=[T(1, "T"), T(2, "A"), T(3, "B")],
                       deps=[D("T", "A"), D("T", "B")])
        c = self.col(r)
        self.assertEqual(c["status"], "pending")
        self.assertEqual([p["type"] for p in c["pending"]], ["unmapped"])
        self.assertIn("B", c["pending"][0]["detail"])

    def test_leaf_task_without_mapping_is_safe(self):
        # A 是叶子任务（无上游依赖），字段无映射不算待核实
        r = self.check(sens_csv(),
                       map_csv(("T", "c", "A", "f", "直传")),
                       tasks=[T(1, "T"), T(2, "A")],
                       deps=[D("T", "A")])
        self.assertEqual(self.col(r)["status"], "safe")

    def test_cycle_pending_but_exposed_still_shown(self):
        # A<->B 成环；另有 T<-S 直传命中敏感源
        tasks = [T(1, "T"), T(2, "A"), T(3, "B"), T(4, "S")]
        deps = [D("T", "A"), D("A", "B"), D("B", "A"), D("T", "S")]
        r = self.check(sens_csv(("S", "g")),
                       map_csv(("T", "c", "A", "f", "直传"),
                               ("A", "f", "B", "f", "直传"),
                               ("B", "f", "A", "f", "直传"),
                               ("T", "c", "S", "g", "直传")),
                       tasks=tasks, deps=deps)
        c = self.col(r)
        self.assertEqual(c["status"], "exposed")  # 裸露优先展示
        self.assertEqual(len(c["exposed_paths"]), 1)
        self.assertEqual([(s["task"], s["field"]) for s in c["exposed_paths"][0]],
                         [("T", "c"), ("S", "g")])
        self.assertTrue(any(p["type"] == "cycle" for p in c["pending"]))

    def test_cycle_only_column_is_pending(self):
        tasks = [T(1, "T"), T(2, "A"), T(3, "B")]
        deps = [D("T", "A"), D("A", "B"), D("B", "A")]
        r = self.check(sens_csv(),
                       map_csv(("T", "c", "A", "f", "直传"),
                               ("A", "f", "B", "f", "直传"),
                               ("B", "f", "A", "f", "直传")),
                       tasks=tasks, deps=deps)
        c = self.col(r)
        self.assertEqual(c["status"], "pending")
        self.assertTrue(any(p["type"] == "cycle" for p in c["pending"]))

    def test_columns_checked_independently(self):
        # c1 裸露、c2 缺映射待核实、c3 脱敏安全 —— 互不影响
        tasks = [T(1, "T"), T(2, "A"), T(3, "B")]
        deps = [D("T", "A"), D("T", "B")]
        r = self.check(sens_csv(("A", "f")),
                       map_csv(("T", "c1", "A", "f", "直传"),
                               ("T", "c3", "A", "f", "脱敏"),
                               ("T", "c3", "B", "f", "脱敏")),
                       columns="c1, c2\nc3", tasks=tasks, deps=deps)
        self.assertEqual(self.col(r, "c1")["status"], "exposed")
        c2 = self.col(r, "c2")
        self.assertEqual(c2["status"], "pending")
        self.assertEqual(len(c2["pending"]), 1)
        self.assertIn("A", c2["pending"][0]["detail"])
        self.assertIn("B", c2["pending"][0]["detail"])
        self.assertEqual(self.col(r, "c3")["status"], "safe")
        self.assertEqual(r["summary"], {"exposed": 1, "pending": 1, "safe": 1})

    def test_sensitive_source_with_further_upstream_also_traced(self):
        # 敏感源节点本身还有更上游的直传映射，两条裸露路径都应列出
        tasks = [T(1, "T"), T(2, "A"), T(4, "S"), T(5, "S2")]
        deps = [D("T", "A"), D("A", "S"), D("S", "S2")]
        r = self.check(sens_csv(("S", "g"), ("S2", "h")),
                       map_csv(("T", "c", "A", "f", "直传"),
                               ("A", "f", "S", "g", "直传"),
                               ("S", "g", "S2", "h", "直传")),
                       tasks=tasks, deps=deps)
        c = self.col(r)
        self.assertEqual(c["status"], "exposed")
        ends = {tuple((s["task"], s["field"]) for s in p)
                for p in c["exposed_paths"]}
        self.assertEqual(ends, {(("T", "c"), ("A", "f"), ("S", "g")),
                                (("T", "c"), ("A", "f"), ("S", "g"), ("S2", "h"))})


class TestValidation(unittest.TestCase):
    def setUp(self):
        self.tasks = [T(1, "T"), T(2, "A")]
        self.deps = [D("T", "A")]

    def check(self, sens, maps, columns="c", target=1):
        return check_lineage(self.tasks, self.deps, sens, maps, target, columns)

    def test_mapping_must_match_existing_dependency(self):
        r = self.check(sens_csv(), map_csv(("T", "c", "ghost", "f", "直传")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("直接依赖" in e for e in r["errors"]))

    def test_bad_mode_rejected(self):
        r = self.check(sens_csv(), map_csv(("T", "c", "A", "f", "加密")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("直传/脱敏" in e for e in r["errors"]))

    def test_conflicting_mode_rejected(self):
        r = self.check(sens_csv(),
                       map_csv(("T", "c", "A", "f", "直传"),
                               ("T", "c", "A", "f", "脱敏")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("冲突" in e for e in r["errors"]))

    def test_bad_header_rejected(self):
        r = self.check(make_csv(["task", "field"], [["A", "f"]]),
                       map_csv(("T", "c", "A", "f", "直传")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("表头" in e for e in r["errors"]))

    def test_oversize_rejected(self):
        big = b"a" * (MAX_CSV_BYTES + 1)
        r = self.check(big, map_csv(("T", "c", "A", "f", "直传")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("256 KiB" in e for e in r["errors"]))
        r2 = self.check(sens_csv(), big)
        self.assertFalse(r2["ok"])

    def test_non_utf8_rejected(self):
        r = self.check(b"\xff\xfe\x00\x01", map_csv(("T", "c", "A", "f", "直传")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("UTF-8" in e for e in r["errors"]))

    def test_empty_columns_rejected(self):
        r = self.check(sens_csv(), map_csv(("T", "c", "A", "f", "直传")),
                       columns="  , ，")
        self.assertFalse(r["ok"])
        self.assertTrue(any("待核查列" in e for e in r["errors"]))

    def test_target_missing_rejected(self):
        r = self.check(sens_csv(), map_csv(("T", "c", "A", "f", "直传")), target=99)
        self.assertFalse(r["ok"])
        self.assertTrue(any("目标任务不存在" in e for e in r["errors"]))

    def test_sensitive_unknown_task_warns_but_ok(self):
        r = self.check(sens_csv(("ghost", "f")),
                       map_csv(("T", "c", "A", "f", "直传")))
        self.assertTrue(r["ok"])
        self.assertTrue(any("ghost" in w for w in r["warnings"]))

    def test_utf8_bom_and_english_mode_accepted(self):
        sens = ("\ufeff任务,字段\nA,f\n").encode("utf-8")
        maps = make_csv(["下游任务", "下游字段", "上游任务", "上游字段", "直传/脱敏"],
                        [["T", "c", "A", "f", "DIRECT"]])
        r = self.check(sens, maps)
        self.assertTrue(r["ok"], r.get("errors"))
        self.assertEqual(r["columns"][0]["status"], "exposed")


if __name__ == "__main__":
    unittest.main()
