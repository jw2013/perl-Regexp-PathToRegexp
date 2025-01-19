# NAME

`Regexp::PathToRegexp` - Turn a path string such as `/user/:name` into a regular expression.

# SYNOPSIS

    use Regexp::PathToRegexp qw(
       match
       path_to_regexp
       compile
       parse
       stringify
    );
    
    *fn = match("/:foo/:bar");
    fn("/test/route");
    # $_ = { path => '/test/route', params => { foo => 'test', bar => 'route' } }

    my $fn = match("/file/{:name}{.:ext}");
    &$fn("/file/test.jpg");
    # $_ = { path => '/file/test.jpg', params => { name => 'test', ext => 'jpg' } }

# DESCRIPTION

This is a port of the excellent Node.js package `path-to-regexp` to the Perl programming language.
The `path-to-regexp` package is a core component of the widely used `express.js` framework. All kudos go to **Blake Embrey** and the other contributors.

The original code/project can be found here:

[https://github.com/pillarjs/path-to-regexp](https://github.com/pillarjs/path-to-regexp)

This Perl package is currently based on the version `8.2` of the original Node.js package, which has been completely rewamped and hardened against ReDoS attacks.

More information about ReDoS attacks can be found here:

- [https://owasp.org/www-community/attacks/Regular\_expression\_Denial\_of\_Service\_-\_ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [https://blakeembrey.com/posts/2024-09-web-redos/](https://blakeembrey.com/posts/2024-09-web-redos/)

# PARAMETERS

Parameters match arbitrary strings in a path by matching up to the end of the segment, or up to any proceeding tokens. They are defined by prefixing a colon to the parameter name (`:foo`). Parameter names can use any valid JavaScript identifier, or be double quoted to use other characters (`:"param-name"`).

    *fn = match("/:foo/:bar");

    fn("/test/route");
    # $_ = { path => '/test/route', params => { foo => 'test', bar => 'route' } }

# WILDCARD

Wildcard parameters match one or more characters across multiple segments. They are defined the same way as regular parameters, but are prefixed with an asterisk (`*foo`).

    *fn = match("/*splat");

    fn("/bar/baz");
    # $_ = { path => '/bar/baz', params => { splat => [ 'bar', 'baz' ] } }

# OPTIONAL

Braces can be used to define parts of the path that are optional.

    *fn = match("/users{/:id}/delete");
    
    fn("/users/delete");
    # $_ = { path => '/users/delete', params => {} }
    
    fn("/users/123/delete");
    # $_ = { path => '/users/123/delete', params => { id => '123' } }

# METHODS

## match

    *fn = match("/foo/:bar");

The `match` function returns a function for matching strings against a path:

- **path** String or array of strings.
- **options** _(optional)_ (Extends path\_to\_regexp options)
    - **decode** Function for decoding strings to params, or `undef` to disable all processing. (default: `decodeURIComponent`)

**Please note:** `Regexp::PathToRegexp` is intended for ordered data (e.g. paths, hosts). It can not handle arbitrarily ordered data (e.g. query strings, URL fragments, JSON, etc).

## path\_to\_regexp

    my ( $regexp, $keys ) = path_to_regexp("/foo/:bar");

The `path_to_regexp` function returns the `regexp` for matching strings against paths,
and an array of `keys` for understanding the `RegExp` matches.

- **path** String or array of strings.
- **options** _(optional)_ (See parse for more options)
    - **sensitive** Regexp will be case sensitive. (default: `0`)
    - **end** Validate the match reaches the end of the string. (default: `1`)
    - **delimiter** The default delimiter for segments, e.g. `[^/]` for `:named` parameters. (default: `'/'`)
    - **trailing** Allows optional trailing delimiter to match. (default: `1`)

## compile ("Reverse" Path-To-RegExp)

    *toPath = compile("/user/:id");
    
    toPath({ id => "name" }); # $_ = "/user/name"
    toPath({ id => "café" }); # $_ = "/user/caf%C3%A9"
    
    *toPathRepeated = compile("/*segment");
    
    toPathRepeated({ segment => ["foo"] }); # $_ = "/foo"
    toPathRepeated({ segment => ["a", "b", "c"] }); # $_ = "/a/b/c"

    # When disabling C<encode>, you need to make sure inputs are encoded correctly. No arrays are accepted.
    *toPathRaw = compile("/user/:id", { encode => 0 });
    
    toPathRaw({ id => "%3A%2F" }); # $_ = "/user/%3A%2F"

The `compile` function will return a function for transforming parameters into a valid path:

- **path** A string.
- **options** _(optional)_ (See parse for more options)
    - **delimiter** The default delimiter for segments, e.g. `[^/]` for `:named` parameters. (default: `'/'`)
    - **encode** Function for encoding input strings for output into the path, or `undef` to disable entirely. (default: `encodeURIComponent`)

## stringify

    my $data = Regexp::PathToRegexp::TokenData->new([
        { type => 'text', value => "/" },
        { type => 'param', name => "foo" },
    ]);
    my $path = stringify($data);    # $path = "/:foo"

The `stringify` transform `TokenData` (a sequence of tokens) back into a Path-to-RegExp string.

- **data** A Regexp::PathToRegexp::TokenData instance

## parse

    my $data = parse("/user/:id"); # ref($data) eq "Regexp::PathToRegexp::TokenData"
    my $path = stringify($data);   # $path = "/user/:id"

The `parse` function accepts a string and returns an instance of `Regexp::PathToRegexp::TokenData`, the set of tokens and other metadata parsed from the input string.

- **path** A string.
- **options** _(optional)_
    - **encodePath** A function for encoding input strings. (default: no encoding)

# AUTHOR

Jens Wagner <jens@wagner2013.de>

Based on the `path-to-regexp` node package:
[https://github.com/pillarjs/path-to-regexp](https://github.com/pillarjs/path-to-regexp)

# COPYRIGHT AND LICENSE

(c)2025 Jens Wagner

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.
