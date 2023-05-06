<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1" />
  <link rel="preload stylesheet" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/10up-sanitize.css/11.0.1/sanitize.min.css" integrity="sha256-PK9q560IAAa6WVRRh76LtCaI8pjTJ2z11v0miyNNjrs=" crossorigin>
  <link rel="preload stylesheet" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/10up-sanitize.css/11.0.1/typography.min.css" integrity="sha256-7l/o7C8jubJiy74VsKTidCy1yBkRtiUGbVkYBylBqUg=" crossorigin>

  <%namespace name="css" file="css.mako" />
  <style>${css.mobile()}</style>
  <style media="screen and (min-width: 700px)">${css.desktop()}</style>
  <style media="print">${css.print()}</style>
  <style>
    header > h1 { text-align: center; }
  </style>
</head>
<body>
  <header>
    <h1>IDAPython documentation</h1>
  </header>
  <main>
    <article id="content">
      <h2>Defined modules:</h2>
      <ul>
      % for mod in modules:
        <li><a href=${mod.url()}>${mod.name}</a></li>
      % endfor
      </ul>
    </article>
    <nav id="sidebar">
      % if lunr_search is not None:
        <%include file="_lunr_search.inc.mako"/>
      % endif
    </nav>
  </main>
</body>
</html>
