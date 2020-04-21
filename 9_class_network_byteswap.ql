import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(MacroInvocation m |
      m.getMacroName().regexpMatch("ntoh(s|l|ll)") and
      m.getExpr() = this
    )
  } 
}

from NetworkByteSwap n
select n, "Network byte swap" 
