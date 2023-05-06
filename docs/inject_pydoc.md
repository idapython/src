
# inject_pydoc.py

This tool is in charge extracting information from the C++ SDK
headers, and inject it into IDAPython's documentation.

## Extracting the C++ SDK information/documentation

The IDAPython build system will run `doxygen` against the SDK headers,
asking it to output all the information it could extract, as `XML`
format for later use - by `inject_pydoc.py`, but not only…

## Applying the documentation

Then, we run `tools/inject_pydoc.py`, to process that `XML`
content and extract documentation about the functions, classes,
methods, variables, etc… that are present in the corresponding
IDAPython module.

## Fixing the input parameters

We cannot blindly apply the SDK documentation, however: some C++
function parameters will turn into output values when converted to
Python, and thus it makes no sense to have those parameters as part of
the IDAPython function documentation. For example, when wrapping

    inline void get_registered_actions(qstrvec_t *out)

into `ida_kernwin.get_registered_actions`, the `out` parameter will
turn into a `list(str)`, so it makes no sense to see the corresponding
C++ header's documentation:

    /// \param out the list of actions to be filled

into the IDAPython documentation.

Fortunately, we can rely on SWiG's help to do that, because even
though SWiG doesn't know how to import C++ header's documentation, it
*will* tell us what parameters are present in the wrapped prototype.

Therefore, we collect the SWiG-generated list of parameters from the
prototype, and simply remove the non-relevant bits from the C++
header's documentation before injecting that into IDAPython.

## Fixing the return values

Because all of that was too easy, IDAPython adds another layer of
complexity (craziness?) for fixing the return values.

When it comes to the input parameters, it's actually _fairly_ easy to
drop the irrelevant bits from the C++ SDK header's documentation: we
know what parameters SWiG will keep & wrap.

But for the return values, it's another story entirely: SWiG doesn't
know (and cannot always reliably know) what type a return value will
have.
In particular when it comes to custom code in `pywraps/` that returns
a `PyObject *`.

Therefore, we have put a mechanism into place, that lets us put a
"wrapper" around _all_ IDAPython functions/class methods, that will
trace/keep track of the types of the values that were passed in, and
the types of the values that were spit out by those functions.

We can then use that wrapper when running tests, collect information
from the tests that were run, process that information, and save it
into `tools/collected_traces.txt`, which will then be used by
`inject_pydoc.py`.

It's worth pointing out that that information is not, and could not
possibly, be generated at build-time: it must be done at another time
(e.g., after running tests), which is very different than the
mechanism used for fixing the parameters (that "simply" relies on the
`doxygen`-parsed `XML`-formatted documentation.)

