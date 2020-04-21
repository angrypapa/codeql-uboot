import cpp

/* 
from FunctionCall call, Function fcn
where
  call.getTarget() = fcn and fcn.getName() = "memcpy"
select call
*/

from FunctionCall call
where call.getTarget().getName() = "memcpy"
select call