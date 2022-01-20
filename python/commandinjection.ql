/**
 * @name Uncontrolled command line
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @sub-severity high
 * @precision high
 * @id py/command-line-injection-custom
 * @tags correctness
 *       security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import python
import semmle.python.security.dataflow.CommandInjection
import semmle.python.security.dataflow.CommandInjectionCustomizations as Customizations
import semmle.python.ApiGraphs
import DataFlow::PathGraph

// enviroment variables and command line arguments
class EnvArgs extends Customizations::CommandInjection::Source {
  EnvArgs() {
    this.getLocation().getFile().getBaseName().matches("command_injection%") and
    (
      // os.getenv('abc')
      this = API::moduleImport("os").getMember("getenv").getACall()
      or
      // os.environ['abc']
      // os.environ.get('abc')
      this = API::moduleImport("os").getMember("environ").getAUse()
      or
      // sys.argv[1]
      this = API::moduleImport("sys").getMember("argv").getAUse()
    )
  }
}

from CommandInjection::Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on $@.", source.getNode(),
  "a user-provided value"
