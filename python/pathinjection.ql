/**
 * @name Customized path injection query
 * @description Customized path injection query
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/path-injection-customized
 * @tags correctness
 *       security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import python
import semmle.python.security.dataflow.PathInjection
import LocalSources

class LocalSources extends Source, EnvArgs { }

from CustomPathNode source, CustomPathNode sink
where pathInjection(source, sink)
select sink, source, sink, "This path depends on $@.", source, "a user-provided value"
