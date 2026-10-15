import zipfile
from pathlib import Path

import pytest

ANALYSIS = "87f2364f-dcd4-49e6-861d-f8d3f351686b"

FVDL = """<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl">
  <Build><SourceBasePath>/build/proj</SourceBasePath></Build>
  <Vulnerabilities>
    <!-- dataflow: taint source in B.java, sink (isDefault) in A.java -->
    <Vulnerability>
      <ClassInfo><Kingdom>Input Validation and Representation</Kingdom><Type>SQL Injection</Type></ClassInfo>
      <InstanceInfo><InstanceID>V1</InstanceID><InstanceSeverity>4.0</InstanceSeverity>
        <Confidence>5.0</Confidence></InstanceInfo>
      <AnalysisInfo><Unified>
        <Context><Function name="query"/><FunctionDeclarationSourceLocation path="src/A.java" line="18"/></Context>
        <Trace><Primary>
          <Entry><Node><SourceLocation path="src/B.java" line="5"/></Node></Entry>
          <Entry><Node isDefault="true"><SourceLocation path="src/A.java" line="20"/></Node></Entry>
        </Primary></Trace>
      </Unified></AnalysisInfo>
    </Vulnerability>
    <!-- primary node reached through NodeRef -->
    <Vulnerability>
      <ClassInfo><Type>Cross-Site Scripting</Type><Subtype>Reflected</Subtype></ClassInfo>
      <InstanceInfo><InstanceID>V2</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>
      <AnalysisInfo><Unified><Trace><Primary>
        <Entry><NodeRef id="7"/></Entry>
      </Primary></Trace></Unified></AnalysisInfo>
    </Vulnerability>
    <Vulnerability>
      <ClassInfo><Type>Path Manipulation</Type></ClassInfo>
      <InstanceInfo><InstanceID>V3</InstanceID></InstanceInfo>
      <AnalysisInfo><Unified><Trace><Primary>
        <Entry><Node isDefault="true"><SourceLocation path="src/C.java" line="3"/></Node></Entry>
      </Primary></Trace></Unified></AnalysisInfo>
    </Vulnerability>
    <Vulnerability>
      <ClassInfo><Type>Password Management</Type><Subtype>Hardcoded Password</Subtype></ClassInfo>
      <InstanceInfo><InstanceID>V4</InstanceID></InstanceInfo>
      <AnalysisInfo><Unified><Trace><Primary>
        <Entry><Node isDefault="true"><SourceLocation path="web/login.jsp" line="1"/></Node></Entry>
      </Primary></Trace></Unified></AnalysisInfo>
    </Vulnerability>
    <!-- same file and category as V1 but the opposite verdict -->
    <Vulnerability>
      <ClassInfo><Type>SQL Injection</Type></ClassInfo>
      <InstanceInfo><InstanceID>V5</InstanceID></InstanceInfo>
      <AnalysisInfo><Unified><Trace><Primary>
        <Entry><Node isDefault="true"><SourceLocation path="src/A.java" line="30"/></Node></Entry>
      </Primary></Trace></Unified></AnalysisInfo>
    </Vulnerability>
  </Vulnerabilities>
  <UnifiedNodePool>
    <Node id="7" isDefault="true"><SourceLocation path="src/A.java" line="44"/></Node>
  </UnifiedNodePool>
</FVDL>
"""

AUDIT = f"""<?xml version="1.0" encoding="UTF-8"?>
<ns2:Audit xmlns:ns2="xmlns://www.fortify.com/schema/audit">
  <ns2:IssueList>
    <!-- Analysis tag first, custom tag second: the old [1] index read "High" -->
    <ns2:Issue instanceId="V1">
      <ns2:Tag id="{ANALYSIS}"><ns2:Value>Not an Issue</ns2:Value></ns2:Tag>
      <ns2:Tag id="custom-risk"><ns2:Value>High</ns2:Value></ns2:Tag>
    </ns2:Issue>
    <!-- a single tag: the old [1] index raised IndexError -->
    <ns2:Issue instanceId="V2">
      <ns2:Tag id="{ANALYSIS}"><ns2:Value>Suspicious</ns2:Value></ns2:Tag>
    </ns2:Issue>
    <ns2:Issue instanceId="V4">
      <ns2:Tag id="{ANALYSIS}"><ns2:Value>Suspicious</ns2:Value></ns2:Tag>
    </ns2:Issue>
    <ns2:Issue instanceId="V5">
      <ns2:Tag id="{ANALYSIS}"><ns2:Value>Suspicious</ns2:Value></ns2:Tag>
    </ns2:Issue>
  </ns2:IssueList>
</ns2:Audit>
"""

INDEX = """<?xml version="1.0" encoding="UTF-8"?>
<index>
  <entry key="/build/proj/src/A.java">src-archive/1</entry>
  <entry key="/build/proj/src/B.java">src-archive/2</entry>
  <entry key="/build/proj/src/C.java">src-archive/3</entry>
</index>
"""

SOURCES = {
    "src-archive/1": "class A { void query() {} }",
    "src-archive/2": "class B {}",
    "src-archive/3": "class C {}",
}


def make_fpr(path: Path, fvdl: str = FVDL, audit: str = AUDIT, sources=None) -> Path:
    sources = SOURCES if sources is None else sources
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("audit.fvdl", fvdl)
        z.writestr("audit.xml", audit)
        z.writestr("src-archive/index.xml", INDEX)
        for name, body in sources.items():
            z.writestr(name, body)
    return path


@pytest.fixture
def fpr_path(tmp_path):
    return make_fpr(tmp_path / "demo.fpr")
