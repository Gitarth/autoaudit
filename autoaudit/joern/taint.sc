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
// outFile: one JSON object per flow: {"rule": ..., "flow": [{file,line,method,code}, ...]}

import io.shiftleft.codepropertygraph.generated.nodes
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

@main def exec(inputPath: String, specFile: String, outFile: String, maxFlows: Int = 200) = {
  if (inputPath.endsWith(".bin") || inputPath.endsWith(".cpg")) importCpg(inputPath)
  else importCode(inputPath)

  val spec = Source.fromFile(specFile).getLines().filter(_.nonEmpty).map(_.split("\t", -1).toList).toList
  val out = new PrintWriter(outFile, "UTF-8")

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

    var written = 0
    var seen = Set.empty[(String, Option[Int], String, Option[Int])]
    if (sources.nonEmpty && sinks.nonEmpty) {
      for (path <- sinks.reachableByFlows(sources) if written < maxFlows) {
        val els = path.elements
        if (els.nonEmpty && !els.exists(matchesAny(_, sanitizers))) {
          val locs = els.map(_.location)
          val key = (locs.head.filename, locs.head.lineNumber.map(_.toInt),
                     locs.last.filename, locs.last.lineNumber.map(_.toInt))
          if (!seen.contains(key)) {
            seen += key
            written += 1
            val steps = els.zip(locs).map { (n, l) =>
              val line = l.lineNumber.map(_.toString).getOrElse("null")
              s"""{"file":${str(l.filename)},"line":$line,"method":${str(l.methodFullName)},"code":${str(n.code.take(300))}}"""
            }
            out.println(s"""{"rule":${str(rule)},"flow":[${steps.mkString(",")}]}""")
          }
        }
      }
    }
    println(s"[autoaudit] rule $rule: ${sources.size} sources, ${sinks.size} sinks, $written flows")
  }
  out.close()
}
