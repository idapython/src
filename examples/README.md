
# IDAPython examples

This directory contains a variety of examples demonstrating
how IDA can be scripted using IDAPython.

## Adding a new example (for Hex-Rays developers)

When adding an example, the author (i.e., a Hex-Rays developer)
must add a corresponding test, making sure the example is properly
tested, and doesn't regress over time (see `idapython-examples`,
and `idapython_hr-examples` test suites.) This has the added benefit
that this ensures our APIs remain stable.

Also, any significant addition to IDAPython APIs should come
with one or many examples, and those should be also put under test
(in other words: it's better if a test relies on a real example,
rather than if it consists of a bunch of IDAPython code our
users will never see, and cannot be inspired from.)

### Best practices

* don't use `idc.py`: some of its operations are a bit too elusive
* don't use `idaapi`: that "hides" the provenance of the
  function/type/item being used, and makes it that much harder to
  group ideas by module
* don't `from <something> import <whatever>`: for the same reason
* use double-quotes for all string literals, unless there's a good
  reason not to do so (e.g., the string literal contains some `"`
  characters, and `\`-escaping them would be inconvenient & make the
  code awkward to read).
  Double-quoted string literals let us grep more predictably & reliably.

## Example header

Every example must have a valid header, holding a one-liner `summary:`,
as well as a description further explaining what the example is about.

Some notes:

* `summary:`: the one-liner must not end with a `.`
* `summary:`: prefer the `list something...` form over the `listing something...`

## Helping our customers, teaching IDAPython in the process

In addition, when a customer asks for help on support@ (or the forums)
and we end up sending a significant body of IDAPython code as a reply,
since that body of code should be tested anyway, it's better to make
a real example out of it ... and, of course, put that example under
test as well.

## Maintaining quality

There should be no such thing as a non-tested example.

## Updating the examples index

All examples are automatically integrated in the examples index.
In order to show user-friendly & relevant information, a proper
header (docstring) needs to be present.
