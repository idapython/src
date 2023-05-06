[HTML version](http://htmlpreview.github.io/?https://github.com/idapython/src/blob/master/examples/index.html)

# IDAPython examples

% for category in sorted(examples):
## Category: {{category}}

  % for example in sorted(examples[category], key=lambda e: e.name):
#### {{example.name}}
<details>
  <summary>{{example.summary}}</summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/{{example.path}}">{{example.path}}</a>

#### Category
{{example.category}}

#### Description
{{example.description if example.description else example.summary}}

    % if example.shortcuts:
#### Shortcut{{'s' if len(example.shortcuts) > 1 else ''}}
{{' '.join(example.shortcuts)}}

    % endif
    % if example.keywords:
#### Keywords
{{' '.join(example.keywords)}}

    % endif
    % if example.imports:
#### Imports
      % for imported in example.imports:
* {{imported}}
      % endfor

    % endif
    % if example.uses:
#### Uses
      % for use in example.uses:
* {{use}}
      % endfor

    % endif
    % if example.see_also:
#### See also
      % for see in example.see_also:
* [{{see}}](#{{see}})
      % endfor

    % endif
    % if example.author:
#### Author
{{example.author}}

    % endif
</blockquote>

  </details>

  % endfor # examples of a category
% endfor   # categories
