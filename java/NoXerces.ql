/**
 * @name Do not use the Xerces Sax Parser
 * @description Do not use the Xerces Sax Parser
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id java/no-xerces-parser
 * @tags security
 */

import java

from MethodAccess parseCall
where parseCall.getCallee().hasQualifiedName("javax.xml.parsers", "SAXParser", "parse")
select parseCall, "Do not call the parse method of the Xerces SAX parser!"
