/**
 * @name Customized XSS
 * @description Customized XSS detection
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @sub-severity high
 * @precision high
 * @id js/xss-customized
 * @tags correctness
 *       security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import javascript

class S extends IfStmt {
  string getURL() { result = "https://github.com/github" }
}

from S i
select i, i.getURL()
