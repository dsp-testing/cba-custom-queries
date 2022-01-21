/**
 * @name Customized SQL injection query
 * @description Customized SQL injection query
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/sql-injection-customized
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.dataflow.SqlInjection
import DataFlow::PathGraph
import LocalSources

class LocalSources extends SqlInjection::Source, EnvArgs { }

from SqlInjection::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
