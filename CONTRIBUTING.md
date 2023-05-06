IDAPython
=========

### Contributing to IDAPython

Anyone with a valid license is welcome to contribute to IDAPython, and pull
requests will be honored provided their nature matches the criteria below.

If you prefer using patches over git/github+pull requests, please send
those to <support@hex-rays.com>.


### What can I contribute?

We at Hex-Rays are currently maintaining the official IDAPython repository.

Because we are not an infinite-sized company and thus have limited resources
([interested?](https://www.hex-rays.com/jobs.shtml)), we have to keep the
scope of IDAPython itself to a manageable size.

Most of IDAPython consists of rather low-level, arguably non-pythonic APIs.
The reason for that is of course not that we have anything against pythonic
APIs, but we have found that:

- what is idiomatic & pythonic to certain users, will not necessarily be
  to the taste of others,
- when trying to provide pythonic/somewhat higher-level APIs, we often
  ended up not providing the lower-level APIs, sometimes making it
  impossible to build your own utilities should the APIs IDAPython provides
  out-of-the box be insufficient, buggy or just not to your taste,
- users are better at coming up with their own layers anyway.
  E.g., https://github.com/tmr232/Sark

Therefore, the most important aspect of any contribution to IDAPython
should not be about making it more pythonic and/or higher-level, but
instead to make sure that its low-level API (which to a significant degree
are generated from the C/C++ IDA SDK by using SWiG) work fine, are
correctly documented, and tested.

That is the approach we took in order to make sane & well-working
higher-level APIs possible at all.


### Should I write a test?

If your changes touch the APIs from a functional perspective (e.g., fix
a bug, or make a new function available), yes.

There is no such thing as a _code_ change in IDAPython, that is not
accompanied by a test, so please go through the trouble of writing one
so we don't have to do it ourselves.

When it comes to other types of pull requests (e.g., documentation),
it should usually not be necessary to write a test.

See also [the best practices for tests & examples](examples/README.md)


### How to write tests?

Pull requests that actually modify IDAPython code, and that come
together with a test script, have a better chance of being accepted,
because we do not happily push code to IDAPython without making sure
we have non-regression mechanisms into place.

While we won't share our non-regression tools, it is enough to say
that many IDAPython APIs can be tested by mimicking the user entering
commands directly into IDA, and looking at the output.

E.g., here is a part of an actual, real test currently running in
our non-regression environment, testing the `refwidth` property of a
`cexpr_t` instance:

```
Python>x = cexpr_t()
Python>x.refwidth
0
Python>x.refwidth = 18
Python>x.refwidth
18
Python>x.refwidth = var_ref_t()
Traceback (most recent call last):
  <snipped file>, <snipped line>, in <module>
  <snipped file>, <snipped line>, in <lambda>
    refwidth = property(                                                                lambda self: self._get_refwidth() if True else 0,                    lambda self, v: True                                                         and self._ensure_no_obj(self._get_refwidth(),"refwidth", False)                  and self._acquire_ownership(v, False)                                  and self._set_refwidth(v))
  <snipped file>, <snipped line>, in _set_refwidth
    return _ida_hexrays.cexpr_t__set_refwidth(self, *args)
TypeError: in method 'cexpr_t__set_refwidth', argument 2 of type 'int'
```

The key points are:

- this represents a "dialog" with IDAPython: input is prepended with
  "Python>", and output is inline
- this describes what should happen when those operations are performed

Sending us similar testing 'scripts' alongside a pull request, will speed
up its integration significantly, since we'll be able to add the test to
our non-regression environment very quickly.

Please also see [the best practices for developing on IDAPython](HOWTO.md)
