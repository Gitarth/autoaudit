// autoaudit taint query for Joern (Scala 3 script).
//
//   joern --script taint.sc --param inputPath=<dir or cpg.bin> \
//         --param specFile=<spec.tsv> --param outFile=<flows.jsonl>
//
// specFile: one tab-separated entry per line, written by autoaudit/joern/__init__.py
//   SOURCE    <rule> call|param|annotated_param <regex>
//   SINK      <rule> call <regex> <argIndex|*>
//   SANITIZER <rule> call <regex>
// Regexes are matched against both a call's name and its methodFullName, so
// rules work whether or not the frontend resolved types.
//
// outFile: one JSON object per source->sink pair:
//   {"rule": ..., "flows": [[{file,line,method,code}, ...], ...]}  (up to maxPaths distinct paths)
//
// semanticsFile (optional): extra library flow summaries, one per line:
//   <Java regex over method full names> TAB <mappings>
// where mappings is a comma list of "src->dst" (0 = receiver, 1.. = arguments, -1 = return
// value); an empty mapping list means "no data flows through this call".
// externalsFile (optional): written with "<fullName> TAB <flows through it>" for every
// library (external) method that appears on a reported flow.
// sinksFile (optional): one JSON object per sink call site of every rule, whether or not a
// flow reaches it: {"rule", "file", "line", "method", "code", "literal_args"} (true when every
// argument the rule watches is a literal).

import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.joern.dataflowengineoss.semanticsloader.{FlowPath, FlowSemantic, FullNameSemantics}
import java.io.PrintWriter
import scala.io.Source

def esc(s: String): String =
  val sb = new StringBuilder
  s.foreach {
    case '"'  => sb ++= "\\\""
    case '\\' => sb ++= "\\\\"
    case '\n' => sb ++= "\\n"
    case '\r' => sb ++= "\\r"
    case '\t' => sb ++= "\\t"
    case c if c < ' ' => sb ++= f"\\u${c.toInt}%04x"
    case c    => sb += c
  }
  sb.toString

def str(s: String): String = "\"" + esc(s) + "\""

def loadSemantics(path: String): List[FlowSemantic] =
  if (path.isEmpty) Nil
  else Source.fromFile(path).getLines().filter(l => l.trim.nonEmpty && !l.startsWith("#")).map { line =>
    val cols = line.split("\t", -1)
    val maps = if (cols.length < 2) Nil else cols(1).split(",").map(_.trim).filter(_.nonEmpty).toList.map { m =>
      val Array(a, b) = m.split("->").map(_.trim.toInt)
      FlowPath.FlowMapping(a, b)
    }
    FlowSemantic(cols(0), maps, true)
  }.toList

@main def exec(inputPath: String, specFile: String, outFile: String, maxFlows: Int = 200, maxPaths: Int = 8,
               semanticsFile: String = "", externalsFile: String = "", sinksFile: String = "") = {
  if (inputPath.endsWith(".bin") || inputPath.endsWith(".cpg")) importCpg(inputPath)
  else importCode(inputPath)

  val extra = loadSemantics(semanticsFile)
  val semantics = if (extra.isEmpty) DefaultSemantics() else FullNameSemantics.fromList(extra).after(DefaultSemantics())
  semantics.initialize(cpg)
  implicit val engineContext: EngineContext = EngineContext(semantics, EngineConfig())
  if (extra.nonEmpty) println(s"[autoaudit] loaded ${extra.size} extra flow summaries")
  val externals = scala.collection.mutable.Map.empty[String, Int].withDefaultValue(0)
  val isExternal = scala.collection.mutable.Map.empty[String, Boolean]
  def external(fullName: String): Boolean =
    isExternal.getOrElseUpdate(fullName, cpg.method.fullNameExact(fullName).isExternal.nonEmpty)
  def calleeOf(n: nodes.AstNode): Option[String] = n match
    case c: nodes.Call if !c.name.startsWith("<operator>") => Some(c.methodFullName)
    case e: nodes.Expression => Iterator(e).inCall.filterNot(_.name.startsWith("<operator>")).methodFullName.headOption
    case _ => None

  val spec = Source.fromFile(specFile).getLines().filter(_.nonEmpty).map(_.split("\t", -1).toList).toList
  val out = new PrintWriter(outFile, "UTF-8")
  val sinkOut = if (sinksFile.nonEmpty) Some(new PrintWriter(sinksFile, "UTF-8")) else None

  def calls(re: String) =
    cpg.call.filter(c => c.name.matches(re) || c.methodFullName.matches(re))

  def matchesAny(n: nodes.AstNode, res: List[String]): Boolean =
    val owners: List[nodes.Call] = n match
      case c: nodes.Call       => List(c)
      case e: nodes.Expression => Iterator(e).inCall.l
      case _                   => Nil
    owners.exists(c => res.exists(r => c.name.matches(r) || c.methodFullName.matches(r)))

  for (rule <- spec.map(_(1)).distinct) {
    val entries = spec.filter(_(1) == rule)
    val sources: List[nodes.CfgNode] = entries.filter(_.head == "SOURCE").flatMap { e =>
      e(2) match
        case "call"            => calls(e(3)).l
        case "param"           => cpg.method.filter(_.fullName.matches(e(3))).parameter.l
        case "annotated_param" => cpg.parameter.filter(_.annotation.name.l.exists(_.matches(e(3)))).l
        case other             => println(s"[autoaudit] unknown source kind $other"); Nil
    }
    val sinks: List[nodes.CfgNode] = entries.filter(_.head == "SINK").flatMap { e =>
      val args = calls(e(3)).argument.l
      if (e.size > 4 && e(4) != "*") args.filter(_.argumentIndex == e(4).toInt)
      else args.filter(_.argumentIndex >= 1)
    }
    val sanitizers = entries.filter(_.head == "SANITIZER").map(_(3))
    sinkOut.foreach { w =>
      sinks.collect { case e: nodes.Expression => e }.groupBy(e => Iterator(e).inCall.l.headOption).foreach {
        case (Some(call), args) =>
          val l = call.location
          val literal = args.forall(_.isInstanceOf[nodes.Literal])
          val line = l.lineNumber.map(_.toString).getOrElse("null")
          w.println(s"""{"rule":${str(rule)},"file":${str(l.filename)},"line":$line,"method":${str(l.methodFullName)},"code":${str(call.code.take(300))},"literal_args":$literal}""")
        case _ =>
      }
    }

    // Group paths by (source, sink): one alert per pair, keeping up to maxPaths distinct
    // paths so downstream feasibility checks can tell "this path is dead" from
    // "every path is dead".
    type Key = (String, Option[Int], String, Option[Int])
    val groups = scala.collection.mutable.LinkedHashMap.empty[Key, scala.collection.mutable.LinkedHashMap[List[(String, Option[Int])], String]]
    if (sources.nonEmpty && sinks.nonEmpty) {
      for (path <- sinks.reachableByFlows(sources)) {
        val els = path.elements
        if (els.nonEmpty && !els.exists(matchesAny(_, sanitizers))) {
          val locs = els.map(_.location)
          val key: Key = (locs.head.filename, locs.head.lineNumber.map(_.toInt),
                          locs.last.filename, locs.last.lineNumber.map(_.toInt))
          if (groups.contains(key) || groups.size < maxFlows) {
            val paths = groups.getOrElseUpdate(key, scala.collection.mutable.LinkedHashMap.empty)
            val sig = locs.map(l => (l.filename, l.lineNumber.map(_.toInt)))
            if (paths.size < maxPaths && !paths.contains(sig)) {
              val steps = els.zip(locs).map { (n, l) =>
                val line = l.lineNumber.map(_.toString).getOrElse("null")
                s"""{"file":${str(l.filename)},"line":$line,"method":${str(l.methodFullName)},"code":${str(n.code.take(300))}}"""
              }
              paths(sig) = "[" + steps.mkString(",") + "]"
              if (paths.size == 1)
                els.flatMap(calleeOf).distinct.filter(external).foreach(fn => externals(fn) += 1)
            }
          }
        }
      }
    }
    for ((_, paths) <- groups)
      out.println(s"""{"rule":${str(rule)},"flows":[${paths.values.mkString(",")}]}""")
    val written = groups.size
    println(s"[autoaudit] rule $rule: ${sources.size} sources, ${sinks.size} sinks, $written flows")
  }
  out.close()
  sinkOut.foreach(_.close())
  if (externalsFile.nonEmpty) {
    val ex = new PrintWriter(externalsFile, "UTF-8")
    externals.toList.sortBy(-_._2).foreach((fn, n) => ex.println(s"$fn\t$n"))
    ex.close()
  }
}
