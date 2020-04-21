/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(MacroInvocation m |
      m.getMacroName().regexpMatch("ntoh(s|l|ll)") and
      m.getExpr() = this
    )
  } 
}
 
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    exists(NetworkByteSwap nbswap
    | source.asExpr() = nbswap)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call
    | call.getTarget().getName() = "memcpy" and
    sink.asExpr() = call.getArgument(2))
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy at " + sink.getNode().getFunction().getName()