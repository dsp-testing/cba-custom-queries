import semmle.python.ApiGraphs

// enviroment variables and command line arguments
class EnvArgs extends DataFlow::Node {
  EnvArgs() {
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
