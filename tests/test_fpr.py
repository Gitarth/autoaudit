from autoaudit.fpr import FPR

from .conftest import FVDL, make_fpr


def by_id(fpr):
    return {f.instance_id: f for f in fpr.findings}


def test_verdict_comes_from_analysis_tag_not_position(fpr_path):
    with FPR.open(fpr_path) as fpr:
        f = by_id(fpr)
    assert f["V1"].analysis == "Not an Issue"  # old code: "High"
    assert f["V2"].analysis == "Suspicious"  # old code: IndexError
    assert f["V3"].analysis is None  # unaudited


def test_verdict_fallback_without_standard_tag_id(tmp_path):
    audit = """<ns2:Audit xmlns:ns2="xmlns://www.fortify.com/schema/audit"><ns2:IssueList>
      <ns2:Issue instanceId="V1">
        <ns2:Tag id="other"><ns2:Value>High</ns2:Value></ns2:Tag>
        <ns2:Tag id="custom-analysis"><ns2:Value>Suspicious</ns2:Value></ns2:Tag>
      </ns2:Issue></ns2:IssueList></ns2:Audit>"""
    with FPR.open(make_fpr(tmp_path / "x.fpr", audit=audit)) as fpr:
        assert by_id(fpr)["V1"].analysis == "Suspicious"


def test_primary_location_is_the_sink_not_the_taint_source(fpr_path):
    with FPR.open(fpr_path) as fpr:
        v1 = by_id(fpr)["V1"]
    assert (v1.path, v1.line) == ("src/A.java", 20)  # old code: src/B.java
    assert (v1.function, v1.function_line) == ("query", 18)


def test_primary_location_through_node_pool(fpr_path):
    with FPR.open(fpr_path) as fpr:
        v2 = by_id(fpr)["V2"]
    assert (v2.path, v2.line) == ("src/A.java", 44)
    assert v2.category == "Cross-Site Scripting: Reflected"


def test_falls_back_to_last_trace_node(tmp_path):
    fvdl = FVDL.replace(
        '<Node isDefault="true"><SourceLocation path="src/A.java" line="20"/>',
        '<Node><SourceLocation path="src/A.java" line="20"/>',
    )
    with FPR.open(make_fpr(tmp_path / "x.fpr", fvdl=fvdl)) as fpr:
        assert by_id(fpr)["V1"].line == 20


def test_source_lookup_via_source_base_path(fpr_path):
    with FPR.open(fpr_path) as fpr:
        assert fpr.read_source("src/A.java") == b"class A { void query() {} }"
        assert fpr.read_source("missing/Nope.java") is None


def test_stats(fpr_path):
    with FPR.open(fpr_path) as fpr:
        s = fpr.stats()
    assert s == {"project": "demo", "total": 5, "Not an Issue": 1, "Suspicious": 3, "Unaudited": 1}
