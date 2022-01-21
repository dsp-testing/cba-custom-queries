/**
 * @name Customized client-side cross-site scripting
 * @description Customized client-side cross-site scripting
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id js/xss-customized
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.security.dataflow.DomBasedXssQuery
import semmle.javascript.frameworks.jQuery
import DataFlow::PathGraph

private DataFlow::SourceNode getAResponseNodeFromAnXHRObject(DataFlow::SourceNode obj) {
  result = obj.getAPropertyRead(any(string s | s = ["responseText", "responseXML", "responseJSON"]))
}

private DataFlow::Node getAnAjaxCallbackDataNode(ClientRequest::Range request) {
  result =
    request.getAMemberCall(any(string s | s = "done" or s = "then")).getCallback(0).getParameter(0)
  or
  result =
    getAResponseNodeFromAnXHRObject(request.getAMemberCall("fail").getCallback(0).getParameter(0))
}

private class JQueryAjaxCall extends ClientRequest::Range {
  JQueryAjaxCall() { this = jquery().getAMemberCall("ajax") }

  override DataFlow::Node getUrl() {
    result = this.getArgument(0) and not exists(this.getOptionArgument(0, _))
    or
    result = this.getOptionArgument([0 .. 1], "url")
  }

  override DataFlow::Node getHost() { none() }

  override DataFlow::Node getADataNode() { result = this.getOptionArgument([0 .. 1], "data") }

  private string getResponseType() {
    this.getOptionArgument([0 .. 1], "dataType").mayHaveStringValue(result)
  }

  override DataFlow::Node getAResponseDataNode(string responseType, boolean promise) {
    (
      responseType = this.getResponseType()
      or
      not exists(this.getResponseType()) and responseType = ""
    ) and
    promise = false and
    (
      result =
        this.getOptionArgument([0 .. 1], "success")
            .getALocalSource()
            .(DataFlow::FunctionNode)
            .getParameter(0)
      or
      result =
        getAResponseNodeFromAnXHRObject(this.getOptionArgument([0 .. 1],
            any(string method | method = "error" or method = "complete"))
              .getALocalSource()
              .(DataFlow::FunctionNode)
              .getParameter(0))
      or
      result = getAnAjaxCallbackDataNode(this)
    )
  }
}

class AJAX extends Source {
  AJAX() { this = any(JQueryAjaxCall jqac).getAResponseDataNode(_, _) }
}

from DataFlow::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where
  (
    cfg instanceof HtmlInjectionConfiguration or
    cfg instanceof JQueryHtmlOrSelectorInjectionConfiguration
  ) and
  cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  sink.getNode().(Sink).getVulnerabilityKind() + " vulnerability due to $@.", source.getNode(),
  "user-provided value"
