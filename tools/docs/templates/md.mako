## Define mini-templates for each portion of the doco.

<%!
  def indent(s, spaces=3):
      new = s.replace('\n', '\n' + ' ' * spaces).replace("@param", "").replace("@return", " return").replace("@retval", " retval").replace("@note", " note")
      return ' ' * spaces + new.strip()
%>

<%!
  def class_indent(s, spaces=4):
      new = s.replace('\n', '\n' + ' ' * spaces).replace("@param", "").replace("@return", " return").replace("@retval", " retval").replace("@note", " note")
      return ' ' * spaces + new.strip()
%>

<%def name="c_deflist(s)">:${class_indent(s)[1:]}</%def>
<%def name="deflist(s)"> ${indent(s)[1:]}</%def>

<%def name="h3(s)">### ${s}
</%def>


<%def name="function(func)" buffered="True">
<%
        returns = show_type_annotations and func.return_annotation() or ''
        if returns:
            returns = ' \N{non-breaking hyphen}> ' + returns
%>
<strong>${func.name}(${", ".join(func.params(annotate=show_type_annotations))})${returns}</strong>           
---------
${func.docstring | deflist}
</%def>

<%def name="method(func)" buffered="True">
<%
        returns = show_type_annotations and func.return_annotation() or ''
        if returns:
            returns = ' \N{non-breaking hyphen}> ' + returns
%>
- <strong>${func.name}(${", ".join(func.params(annotate=show_type_annotations))})${returns}</strong>           
${func.docstring | deflist}
---

</%def>

<%def name="variable(var)" buffered="True">
<%
        annot = show_type_annotations and var.type_annotation() or ''
        if annot:
            annot = ': ' + annot
%>
${var.name}${annot}           
---------
${var.docstring | class_indent}
</%def>

<%def name="class_variable(var)" buffered="True">
<%
        annot = show_type_annotations and var.type_annotation() or ''
        if annot:
            annot = ': ' + annot
%>
- ${var.name}${annot}           
`${var.docstring | deflist}`
---
</%def>

<%def name="class_(cls)" buffered="True">
${cls.name}(${", ".join(cls.params(annotate=show_type_annotations))})           
---------
${cls.docstring | c_deflist}
<%
  class_vars = cls.class_variables(show_inherited_members, sort=sort_identifiers)
  static_methods = cls.functions(show_inherited_members, sort=sort_identifiers)
  inst_vars = cls.instance_variables(show_inherited_members, sort=sort_identifiers)
  methods = cls.methods(show_inherited_members, sort=sort_identifiers)
  mro = cls.mro()
  subclasses = cls.subclasses()
%>
% if mro:
${h3('Ancestors (in MRO)')}
    % for c in mro:
    * ${c.refname}
    % endfor

% endif
% if subclasses:
${h3('Descendants')}
    % for c in subclasses:
    * ${c.refname}
    % endfor

% endif
% if class_vars:
${h3('Class variables')}
    % for v in class_vars:
${class_variable(v)}

    % endfor
% endif
% if static_methods:
${h3('Static methods')}
    % for f in static_methods:
${method(f)}

    % endfor
% endif
% if inst_vars:
${h3('Instance variables')}
    % for v in inst_vars:
${class_variable(v)}

    % endfor
% endif
% if methods:
${h3('Methods')}
    % for m in methods:
${method(m)}

    % endfor
% endif
</%def>

## Start the output logic for an entire module.

<%
  variables = module.variables(sort=sort_identifiers)
  classes = module.classes(sort=sort_identifiers)
  functions = module.functions(sort=sort_identifiers)
  submodules = module.submodules()
  heading = 'Namespace' if module.is_namespace else 'Module'
%>

${heading} ${module.name}
=${'=' * (len(module.name) + len(heading))}
${module.docstring}


% if submodules:
Sub-modules
===========
    % for m in submodules:
* ${m.name}
    % endfor
% endif

% if variables:
Global Variables
================
    % for v in variables:
${variable(v)}
    % endfor
% endif

% if functions:
Functions
=========
    % for f in functions:
${function(f)}
    % endfor
% endif

% if classes:
Classes
=======
    % for c in classes:
${class_(c)}
    % endfor
% endif
