/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @sub-severity high
 * @precision high
 * @id py/path-injection
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
import semmle.python.ApiGraphs

// enviroment variables and command line arguments
class EnvArgs extends Source {
  Env() {
    // os.getenv('abc')
    this = API::moduleImport("os").getMember("getenv").getACall()
    or
    // os.environ['abc']
    // os.environ.get('abc')
    this = API::moduleImport("os").getMember("environ").getAUse()
    or
    // sys.argv[1]
    this = API::moduleImport("sys").getMember("argv").getAUse()
  }
}

from CustomPathNode source, CustomPathNode sink
where pathInjection(source, sink)
select sink, source, sink, "This path depends on $@.", source, "a user-provided value"
