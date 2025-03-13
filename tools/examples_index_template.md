
# Examples

## IDAPython examples

This collection of examples organizes all IDAPython sample code into [categories](#example-categories-overview) for easy reference. Each example demonstrates practical implementation for the IDAPython API, complementing the [reference documentation](https://python.docs.hex-rays.com/) with a real-world usage scenario.

### How to run the examples?

#### Load the script via File Loader

1. Navigate to **File -> Script file...**.
2. In the new dialog, select the `.py` script you want to run and click **Open**.

#### Load the script via Script command

1. Navigate to **File -> Script command...**.
2. Paste the code into _Please enter script body_ field and click **Run**.

#### Load the script via output window/console

1. In the output window/IDAPython console, type the following command: `exec(open("path/to/your_script.py").read())` to execute the script.

## Example Categories: Overview

<table data-full-width="false">
<thead><tr><th width="256"></th><th></th></tr></thead>
<tbody>

% for c in sorted(categories.categories, key=lambda c: c.rank):
  <tr>
    <td><a href="#{{c.id}}">{{c.label}}</a></td>
    <td>{{c.description}}</td>
  </tr>
% endfor # categories

</tbody>
</table>


% for c in sorted(categories.categories, key=lambda c: c.rank):

## {{c.label}} {#{{c.id}}}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

 % for l in sorted(c.levels, key=lambda l: l.rank):
<tr>
  <td>{{l.label}}</td>
  <td><ul>{{"".join(["<li><a href='#%s'>%s</a></li>" % (e.name, e.summary) for e in sorted(l.examples, key=lambda e: e.name)])}}</ul></td>
</tr>
 % endfor # levels

</tbody>
</table>

% endfor # categories


***

## Examples list

% for c in sorted(categories.categories, key=lambda c: c.rank):
 % for l in sorted(c.levels, key=lambda l: l.rank):
  % for e in sorted(l.examples, key=lambda e: e.name):

### {{e.summary}} {#{{e.name}}}
{{e.description}}

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [{{e.file_name}}](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/{{e.path}}) | {{' '.join(e.keywords)}} | {{l.label}} |

   % if e.uses:
**APIs Used:**
    % for use in e.uses:
* `{{use}}`
    % endfor
   % endif

***

  % endfor # examples
 % endfor # levels
% endfor # categories
